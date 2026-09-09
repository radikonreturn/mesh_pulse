"""Protocol-v3 cancellation, collision, partial, and resume tests."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.inbox import IncomingRequestManager
from mesh_pulse.core.resume import (
    PartialTransferStore,
    commit_partial_file,
    resolve_destination_collision,
)
from mesh_pulse.core.session import AuthenticationError, ProtocolError
from mesh_pulse.core.transfer import (
    FileClient,
    FileServer,
    TransferStatus,
    _recv_frame_bytes,
    _recv_frame_json,
)
from mesh_pulse.core.transfer_protocol import validate_offer
from mesh_pulse.core.trust import TrustStatus, TrustStore
from mesh_pulse.utils.config import CHUNK_SIZE


def _port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _pair(tmp_path):
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_store = TrustStore(tmp_path / "client-trust.json")
    server_store = TrustStore(tmp_path / "server-trust.json")
    client_store.trust(server_identity.device_id, "server", server_identity.public_key)
    server_store.trust(client_identity.device_id, "client", client_identity.public_key)
    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
    )
    return client_identity, server_identity, client_store, server_store, peer


def _wait(client: FileClient, terminal: set[TransferStatus], timeout: float = 5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        records = client.get_transfers()
        if records and records[-1].status in terminal:
            return records
        time.sleep(0.02)
    return client.get_transfers()


def _client_server(tmp_path, manager, *, progress=None):
    client_id, server_id, client_store, server_store, peer = _pair(tmp_path)
    port = _port()
    receive_dir = tmp_path / "received"
    server = FileServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_id,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
        approval_timeout=1,
    )
    client = FileClient(
        port=port,
        identity=client_id,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
        approval_timeout=1,
        on_progress=progress,
    )
    return server, client, receive_dir


def test_filename_collision_preserves_extension(tmp_path):
    receive_dir = tmp_path / "received"
    receive_dir.mkdir()
    (receive_dir / "report.pdf").write_bytes(b"one")
    (receive_dir / "report (1).pdf").write_bytes(b"two")
    assert resolve_destination_collision(receive_dir, "report.pdf").name == (
        "report (2).pdf"
    )
    with pytest.raises(ValueError):
        resolve_destination_collision(receive_dir, "../report.pdf")


def test_invalid_resume_offset_and_metadata_rejected():
    offer = validate_offer(
        {
            "type": "transfer_offer",
            "version": 3,
            "transfer_id": "a" * 32,
            "count": 1,
            "total_size": 10,
            "files": [
                {
                    "file_id": "file-0",
                    "name": "a.bin",
                    "size": 10,
                    "sha256": "b" * 64,
                }
            ],
        }
    )
    with pytest.raises(ProtocolError, match="offset"):
        PartialTransferStore.validate_resume_state(
            {
                "type": "resume_state",
                "transfer_id": offer.transfer_id,
                "files": [{"file_id": "file-0", "offset": 11}],
            },
            offer,
        )
    with pytest.raises(ProtocolError, match="metadata mismatch"):
        PartialTransferStore.validate_resume_query(
            {
                "type": "resume_query",
                "transfer_id": offer.transfer_id,
                "files": [],
            },
            offer,
        )


def test_sender_cancelled_while_waiting_never_writes_payload(tmp_path):
    manager = IncomingRequestManager()
    server, client, receive_dir = _client_server(tmp_path, manager)
    source = tmp_path / "cancel.bin"
    source.write_bytes(os.urandom(128 * 1024))
    server.start()
    time.sleep(0.05)
    try:
        transfer_id = client.send("127.0.0.1", str(source))
        deadline = time.time() + 2
        while time.time() < deadline and not manager.get_pending_requests():
            time.sleep(0.01)
        assert client.cancel_transfer(transfer_id)
        records = _wait(client, {TransferStatus.CANCELLED})
        assert records[-1].status == TransferStatus.CANCELLED
        assert not (receive_dir / source.name).exists()
    finally:
        manager.reject_request(transfer_id)
        server.shutdown()


def test_resume_from_valid_partial_and_final_hash(tmp_path):
    receive_dir = tmp_path / "received"
    source = tmp_path / "resume.bin"
    content = os.urandom(180 * 1024)
    source.write_bytes(content)

    holder: list[IncomingRequestManager] = []

    def seed_and_accept(request) -> None:
        partial_dir = receive_dir / ".mesh-pulse-partials" / request.transfer_id
        partial_dir.mkdir(parents=True)
        prefix = content[:65536]
        (partial_dir / "file-0.part").write_bytes(prefix)
        metadata = {
            "transfer_id": request.transfer_id,
            "files": {
                "file-0": {
                    "name": source.name,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            },
        }
        (partial_dir / "metadata.json").write_text(json.dumps(metadata))
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(seed_and_accept)
    holder.append(manager)
    server, client, receive_dir = _client_server(tmp_path, manager)
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        records = _wait(client, {TransferStatus.COMPLETE})
        assert records[-1].status == TransferStatus.COMPLETE
        assert records[-1].resume_offset == 65536
        assert records[-1].bytes_transferred_this_attempt == len(content) - 65536
        assert (receive_dir / source.name).read_bytes() == content
    finally:
        server.shutdown()


def test_collision_is_used_by_completed_v3_transfer(tmp_path):
    holder: list[IncomingRequestManager] = []

    def accept(request) -> None:
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    server, client, receive_dir = _client_server(tmp_path, manager)
    receive_dir.mkdir(parents=True, exist_ok=True)
    (receive_dir / "same.txt").write_text("existing")
    source = tmp_path / "same.txt"
    source.write_text("incoming")
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        assert _wait(client, {TransferStatus.COMPLETE})[-1].status == (
            TransferStatus.COMPLETE
        )
        assert (receive_dir / "same.txt").read_text() == "existing"
        assert (receive_dir / "same (1).txt").read_text() == "incoming"
    finally:
        server.shutdown()


def test_authentication_failure_is_not_retried(tmp_path, monkeypatch):
    identity = DeviceIdentity.load_or_create(tmp_path / "client")
    store = TrustStore(tmp_path / "trust.json")
    peer = SimpleNamespace(
        device_id="mp-12345678",
        public_key=identity.public_key,
        trust_status=TrustStatus.NEW,
        protocol_version=3,
    )
    source = tmp_path / "blocked.bin"
    source.write_bytes(b"blocked")
    client = FileClient(
        identity=identity,
        trust_store=store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
    )
    calls = 0

    def fail_auth(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AuthenticationError("untrusted")

    monkeypatch.setattr(client, "_send_session", fail_auth)
    client._batch_worker(
        "127.0.0.1",
        [str(source)],
        None,
        "f" * 32,
        threading.Event(),
    )
    records = client.get_transfers()
    assert calls == 1
    assert records[-1].retry_count == 0


def test_protocol_failure_is_not_retried(tmp_path, monkeypatch):
    source = tmp_path / "protocol.bin"
    source.write_bytes(b"protocol")
    client = FileClient()
    calls = 0

    def fail_protocol(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise ProtocolError("malformed response")

    monkeypatch.setattr(client, "_send_session", fail_protocol)
    client._batch_worker(
        "127.0.0.1",
        [str(source)],
        None,
        "e" * 32,
        threading.Event(),
    )
    assert calls == 1
    assert client.get_transfers()[-1].retry_count == 0


def test_active_cancel_keeps_only_hidden_partial(tmp_path):
    holder: list[IncomingRequestManager] = []

    def accept(request) -> None:
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    client_holder: list[FileClient] = []
    cancelled = False

    def cancel_after_chunk(_name: str, _sent: int, _size: int) -> None:
        nonlocal cancelled
        if not cancelled:
            cancelled = True
            info = client_holder[0].get_transfers()[0]
            client_holder[0].cancel_transfer(info.transfer_id)

    server, client, receive_dir = _client_server(
        tmp_path, manager, progress=cancel_after_chunk
    )
    client_holder.append(client)
    source = tmp_path / "partial.bin"
    source.write_bytes(os.urandom(CHUNK_SIZE * 4))
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        records = _wait(client, {TransferStatus.CANCELLED})
        assert records[-1].status == TransferStatus.CANCELLED
        assert not (receive_dir / source.name).exists()
        partials = list((receive_dir / ".mesh-pulse-partials").rglob("*.part"))
        assert partials and partials[0].stat().st_size == CHUNK_SIZE
    finally:
        server.shutdown()


class _InterruptOnceServer(FileServer):
    interrupted = False

    def _receive_v3_file_data(
        self, conn, session_key, offer, offered, partial_path, info
    ) -> None:
        if self.interrupted:
            return super()._receive_v3_file_data(
                conn, session_key, offer, offered, partial_path, info
            )
        control = _recv_frame_json(conn, session_key)
        assert control["offset"] == 0
        data = _recv_frame_bytes(conn, session_key)
        partial_path.parent.mkdir(parents=True, exist_ok=True)
        partial_path.write_bytes(data)
        info.bytes_transferred = len(data)
        self.interrupted = True
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        raise ConnectionResetError("simulated interruption")


def test_temporary_network_interruption_resumes(tmp_path):
    holder: list[IncomingRequestManager] = []

    def accept(request) -> None:
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    client_id, server_id, client_store, server_store, peer = _pair(tmp_path)
    port = _port()
    receive_dir = tmp_path / "received"
    server = _InterruptOnceServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_id,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
        approval_timeout=1,
    )
    client = FileClient(
        port=port,
        identity=client_id,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
        approval_timeout=1,
    )
    source = tmp_path / "interrupted.bin"
    content = os.urandom(CHUNK_SIZE * 3)
    source.write_bytes(content)
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        records = _wait(client, {TransferStatus.COMPLETE}, timeout=8)
        assert records[-1].status == TransferStatus.COMPLETE
        assert records[-1].retry_count == 1
        assert records[-1].resume_offset == CHUNK_SIZE
        assert (receive_dir / source.name).read_bytes() == content
    finally:
        server.shutdown()


def test_receiver_resume_reuses_logical_record_and_no_ghost(tmp_path):
    """Test 1 & Test 3: Receiver reuses logical record on resume; no ghost active/interrupted transfer."""
    holder: list[IncomingRequestManager] = []

    def accept(request) -> None:
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    client_id, server_id, client_store, server_store, peer = _pair(tmp_path)
    port = _port()
    receive_dir = tmp_path / "received"
    server = _InterruptOnceServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_id,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
        approval_timeout=1,
    )
    client = FileClient(
        port=port,
        identity=client_id,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
        approval_timeout=1,
    )
    source = tmp_path / "resume_record.bin"
    content = os.urandom(CHUNK_SIZE * 3)
    source.write_bytes(content)
    server.start()
    time.sleep(0.05)
    try:
        client.send("127.0.0.1", str(source))
        client_records = _wait(client, {TransferStatus.COMPLETE}, timeout=8)
        assert client_records[-1].status == TransferStatus.COMPLETE

        # Assert receiver runtime records contain exactly one logical record for transfer_id + file_id
        server_records = server.get_transfers()
        assert len(server_records) == 1
        assert server_records[0].status == TransferStatus.COMPLETE
        assert server_records[0].resume_offset > 0
        assert server_records[0].resume_offset == CHUNK_SIZE
        assert server_records[0].bytes_transferred == len(content)
        # There must be no stale receiver-side INTERRUPTED duplicate
        assert not any(r.status == TransferStatus.INTERRUPTED for r in server_records)
    finally:
        server.shutdown()


class _InterruptOnSecondFileServer(FileServer):
    interrupted = False

    def _receive_v3_file_data(
        self, conn, session_key, offer, offered, partial_path, info
    ) -> None:
        if offered.name == "file2.bin" and not self.interrupted:
            control = _recv_frame_json(conn, session_key)
            assert control["offset"] == 0
            data = _recv_frame_bytes(conn, session_key)
            partial_path.parent.mkdir(parents=True, exist_ok=True)
            partial_path.write_bytes(data)
            info.bytes_transferred = len(data)
            self.interrupted = True
            conn.shutdown(socket.SHUT_RDWR)
            conn.close()
            raise ConnectionResetError("simulated interruption on file 2")
        return super()._receive_v3_file_data(
            conn, session_key, offer, offered, partial_path, info
        )


def test_multifile_resume_aggregation(tmp_path):
    """Test 4: Multi-file resume aggregation preserves logical counts and byte totals."""
    holder: list[IncomingRequestManager] = []

    def accept(request) -> None:
        holder[0].accept_request(request.transfer_id)

    manager = IncomingRequestManager(accept)
    holder.append(manager)
    client_id, server_id, client_store, server_store, peer = _pair(tmp_path)
    port = _port()
    receive_dir = tmp_path / "received"
    server = _InterruptOnSecondFileServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_id,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
        approval_timeout=1,
    )
    client = FileClient(
        port=port,
        identity=client_id,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
        approval_timeout=1,
    )
    f1 = tmp_path / "file1.bin"
    f2 = tmp_path / "file2.bin"
    c1 = os.urandom(CHUNK_SIZE * 2)
    c2 = os.urandom(CHUNK_SIZE * 3)
    f1.write_bytes(c1)
    f2.write_bytes(c2)

    server.start()
    time.sleep(0.05)
    try:
        client.send_batch("127.0.0.1", [str(f1), str(f2)])
        records = _wait(client, {TransferStatus.COMPLETE}, timeout=10)
        assert len(records) == 2
        assert all(r.status == TransferStatus.COMPLETE for r in records)

        server_records = server.get_transfers()
        assert len(server_records) == 2
        assert all(r.status == TransferStatus.COMPLETE for r in server_records)
        assert sum(r.bytes_transferred for r in server_records) == len(c1) + len(c2)
        assert not any(r.status == TransferStatus.INTERRUPTED for r in server_records)
    finally:
        server.shutdown()


def test_hardlink_fallback(tmp_path, monkeypatch):
    """Test 8: Fallback when os.link fails with a filesystem error."""

    def mock_link_fail(src, dst):
        raise OSError(18, "Invalid cross-device link")

    monkeypatch.setattr(os, "link", mock_link_fail)

    recv_dir = tmp_path / "received"
    recv_dir.mkdir(parents=True, exist_ok=True)

    # 1. Verified file still completes
    partial = tmp_path / "file.part"
    content = b"fallback content verified"
    partial.write_bytes(content)

    dest1 = commit_partial_file(partial, recv_dir, "doc.txt")
    assert dest1.read_bytes() == content
    assert dest1.name == "doc.txt"
    assert not partial.exists()

    # 2. Collision naming still works, existing file is not overwritten
    partial2 = tmp_path / "file2.part"
    content2 = b"second file content"
    partial2.write_bytes(content2)

    dest2 = commit_partial_file(partial2, recv_dir, "doc.txt")
    assert dest1.read_bytes() == content
    assert dest2.read_bytes() == content2
    assert dest2.name == "doc (1).txt"
    assert not partial2.exists()

    # 3. No temporary incomplete files remain
    temp_files = list(recv_dir.glob(".tmp-commit-*"))
    assert len(temp_files) == 0
