"""SQLite transfer history repository tests."""

from __future__ import annotations

import os
import socket
import sqlite3
import time
from dataclasses import replace
from types import SimpleNamespace

from mesh_pulse.core.history import (
    SCHEMA_VERSION,
    TransferFileRecord,
    TransferHistoryStore,
    TransferRecord,
)
from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.transfer import (
    FileServer,
    SecureTransfer,
    TransferStatus,
    _recv_frame_bytes,
    _recv_frame_json,
)
from mesh_pulse.core.trust import TrustStatus, TrustStore


def _record(
    transfer_id: str = "a" * 32,
    *,
    peer_id: str | None = "mp-12345678",
    peer_ip: str = "192.0.2.1",
    direction: str = "send",
    status: str = "active",
) -> TransferRecord:
    return TransferRecord(
        transfer_id=transfer_id,
        peer_device_id=peer_id,
        peer_ip=peer_ip,
        peer_hostname="workstation",
        direction=direction,
        status=status,
        message="project files",
        file_count=1,
        total_size=12,
        bytes_transferred=3,
        started_at=time.time(),
    )


def _file(transfer_id: str = "a" * 32) -> TransferFileRecord:
    return TransferFileRecord(
        id=None,
        transfer_id=transfer_id,
        file_id="file-0",
        filename="report.pdf",
        final_path=None,
        filesize=12,
        sha256="b" * 64,
        bytes_transferred=3,
        status="active",
    )


def test_database_migration_initialization(tmp_path):
    store = TransferHistoryStore(tmp_path / "history.db")
    assert store.available
    with sqlite3.connect(store.path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(transfer_files)"
        ).fetchall()
    assert foreign_keys


def test_history_and_files_survive_reopen(tmp_path):
    path = tmp_path / "history.db"
    store = TransferHistoryStore(path)
    assert store.create_transfer(_record(), [_file()])
    reopened = TransferHistoryStore(path)
    record = reopened.get_transfer("a" * 32)
    assert record is not None
    assert record.status == "interrupted"
    assert reopened.get_files(record.transfer_id)[0].filename == "report.pdf"


def test_status_updates_and_peer_global_filters(tmp_path):
    store = TransferHistoryStore(tmp_path / "history.db")
    store.create_transfer(_record("a" * 32, status="pending_approval"), [_file()])
    store.create_transfer(
        _record(
            "b" * 32,
            peer_id="mp-87654321",
            peer_ip="192.0.2.2",
            direction="recv",
            status="failed",
        )
    )
    assert store.update_transfer(
        "a" * 32,
        status="complete",
        bytes_transferred=12,
        completed_at=time.time(),
    )
    assert store.update_file(
        "a" * 32, "file-0", status="complete", bytes_transferred=12
    )
    assert store.list_for_peer("mp-12345678", "198.51.100.1")[0].status == ("complete")
    assert [item.direction for item in store.list_transfers(direction="recv")] == [
        "recv"
    ]
    assert [item.status for item in store.list_transfers(status="failed")] == ["failed"]
    assert store.search("workstation")


def test_active_becomes_interrupted_after_simulated_restart(tmp_path):
    path = tmp_path / "history.db"
    first = TransferHistoryStore(path)
    first.create_transfer(_record(status="active"))
    second = TransferHistoryStore(path)
    assert second.get_transfer("a" * 32).status == "interrupted"


def test_corrupted_database_is_handled_safely(tmp_path):
    path = tmp_path / "history.db"
    path.write_bytes(b"not a sqlite database")
    store = TransferHistoryStore(path)
    assert not store.available
    assert store.list_transfers() == []
    assert not store.create_transfer(_record())


def test_locked_database_failure_is_handled_safely(tmp_path):
    store = TransferHistoryStore(tmp_path / "history.db")
    locker = sqlite3.connect(store.path)
    locker.execute("BEGIN EXCLUSIVE")
    try:
        assert not store.create_transfer(_record())
    finally:
        locker.rollback()
        locker.close()


def test_clear_history_does_not_delete_received_files(tmp_path):
    received = tmp_path / "received" / "report.pdf"
    received.parent.mkdir()
    received.write_bytes(b"contents")
    store = TransferHistoryStore(tmp_path / "history.db")
    file_record = replace(_file(), final_path=str(received))
    store.create_transfer(_record(status="complete"), [file_record])
    assert store.clear()
    assert store.list_transfers() == []
    assert received.read_bytes() == b"contents"


def test_transfer_lifecycle_is_persisted_for_sender_and_receiver(tmp_path):
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)
    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="server",
    )
    server_history = TransferHistoryStore(tmp_path / "server-history.db")
    client_history = TransferHistoryStore(tmp_path / "client-history.db")
    server_holder = []

    def approve(request) -> None:
        server_holder[0].accept_request(request.transfer_id)

    server = SecureTransfer(
        transfer_port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        history_store=server_history,
        on_incoming_request=approve,
    )
    server_holder.append(server)
    client = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
        history_store=client_history,
    )
    source = tmp_path / "persistent.bin"
    source.write_bytes(b"persistent history")
    server.start_server()
    time.sleep(0.05)
    try:
        transfer_id = client.send_file("127.0.0.1", str(source))
        deadline = time.time() + 5
        while time.time() < deadline:
            record = client_history.get_transfer(transfer_id)
            if record and record.status == TransferStatus.COMPLETE.value:
                break
            time.sleep(0.02)
        sent = TransferHistoryStore(client_history.path).get_transfer(transfer_id)
        received = TransferHistoryStore(server_history.path).get_transfer(transfer_id)
        assert sent is not None and sent.status == "complete"
        assert received is not None and received.status == "complete"
        assert sent.bytes_transferred == source.stat().st_size
        assert received.bytes_transferred == source.stat().st_size
        assert client_history.get_files(transfer_id)[0].status == "complete"
    finally:
        server.stop_server()


def test_cancel_status_is_persisted(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    peer_identity = DeviceIdentity.load_or_create(tmp_path / "peer")
    trust = TrustStore(tmp_path / "trust.json")
    trust.trust(peer_identity.device_id, "peer", peer_identity.public_key)
    peer = SimpleNamespace(
        device_id=peer_identity.device_id,
        public_key=peer_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="peer",
    )
    history = TransferHistoryStore(tmp_path / "history.db")
    transfer = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
        history_store=history,
    )
    source = tmp_path / "cancel.bin"
    source.write_bytes(b"cancel")
    transfer_id = transfer.send_file("127.0.0.1", str(source))
    assert transfer.cancel_transfer(transfer_id)
    deadline = time.time() + 2
    while time.time() < deadline:
        record = history.get_transfer(transfer_id)
        if record and record.status == "cancelled":
            break
        time.sleep(0.01)
    assert history.get_transfer(transfer_id).status == "cancelled"


class _HistoryInterruptOnceServer(FileServer):
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


def test_receiver_persistent_history_after_resume(tmp_path):
    """Test 2: Receiver persistent history shows COMPLETE, not INTERRUPTED, no byte/count duplication."""
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()

    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)

    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="server",
    )
    server_history = TransferHistoryStore(tmp_path / "server-history.db")
    client_history = TransferHistoryStore(tmp_path / "client-history.db")
    server_holder = []

    def approve(request) -> None:
        server_holder[0].accept_request(request.transfer_id)

    server = SecureTransfer(
        transfer_port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        history_store=server_history,
        on_incoming_request=approve,
    )
    server_holder.append(server)

    # Swap in the interrupting server
    server._server = _HistoryInterruptOnceServer(
        port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        incoming_manager=server._incoming,
        on_transfer_update=server._handle_transfer_update,
        approval_timeout=5,
    )

    client = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
        history_store=client_history,
    )

    source = tmp_path / "resume_history.bin"
    content = os.urandom(64 * 1024 * 3)
    source.write_bytes(content)

    server.start_server()
    time.sleep(0.05)
    try:
        transfer_id = client.send_file("127.0.0.1", str(source))
        deadline = time.time() + 10
        while time.time() < deadline:
            record = server_history.get_transfer(transfer_id)
            if record and record.status == "complete":
                break
            time.sleep(0.05)

        # Force a flush of runtime transfers to history if not yet flushed
        server._handle_transfer_update()

        record = server_history.get_transfer(transfer_id)
        assert record is not None
        assert record.status == "complete"
        assert record.bytes_transferred == len(content)
        assert record.file_count == 1
        assert record.total_size == len(content)

        files = server_history.get_files(transfer_id)
        assert len(files) == 1
        assert files[0].status == "complete"
        assert files[0].bytes_transferred == len(content)
    finally:
        server.stop_server()


def test_rejected_child_history(tmp_path):
    """Test 5: When request is rejected, parent is REJECTED and all child files are REJECTED."""
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()

    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)

    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="server",
    )
    server_history = TransferHistoryStore(tmp_path / "server-history.db")
    server_holder = []

    def reject(request) -> None:
        server_holder[0].reject_request(request.transfer_id)

    server = SecureTransfer(
        transfer_port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        history_store=server_history,
        on_incoming_request=reject,
    )
    server_holder.append(server)

    client = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
    )

    source = tmp_path / "rejected.bin"
    source.write_bytes(b"content")

    server.start_server()
    time.sleep(0.05)
    try:
        transfer_id = client.send_file("127.0.0.1", str(source))
        deadline = time.time() + 5
        while time.time() < deadline:
            record = server_history.get_transfer(transfer_id)
            files = server_history.get_files(transfer_id)
            if (
                record
                and record.status == "rejected"
                and files
                and files[0].status == "rejected"
            ):
                break
            time.sleep(0.02)

        record = server_history.get_transfer(transfer_id)
        assert record is not None
        assert record.status == "rejected"
        files = server_history.get_files(transfer_id)
        assert len(files) == 1
        assert files[0].status == "rejected"
    finally:
        server.stop_server()


def test_expired_child_history(tmp_path):
    """Test 6: When request expires, parent is FAILED with reason and all children are FAILED."""
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()

    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)

    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="server",
    )
    server_history = TransferHistoryStore(tmp_path / "server-history.db")

    # Set approval_timeout very short to expire quickly
    server = SecureTransfer(
        transfer_port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        history_store=server_history,
        on_incoming_request=lambda _req: None,
        approval_timeout=0.2,
    )

    client = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
        approval_timeout=5.0,
    )

    source = tmp_path / "expired.bin"
    source.write_bytes(b"content")

    server.start_server()
    time.sleep(0.05)
    try:
        transfer_id = client.send_file("127.0.0.1", str(source))
        deadline = time.time() + 5
        while time.time() < deadline:
            record = server_history.get_transfer(transfer_id)
            files = server_history.get_files(transfer_id)
            if (
                record
                and record.status == "failed"
                and files
                and files[0].status == "failed"
            ):
                break
            time.sleep(0.02)

        record = server_history.get_transfer(transfer_id)
        assert record is not None
        assert record.status == "failed"
        assert record.error == "Transfer request expired"
        files = server_history.get_files(transfer_id)
        assert len(files) == 1
        assert files[0].status == "failed"
    finally:
        server.stop_server()


def test_cancelled_child_history(tmp_path):
    """Test 7: When request is cancelled, parent is CANCELLED and all children are CANCELLED."""
    port_socket = socket.socket()
    port_socket.bind(("127.0.0.1", 0))
    port = port_socket.getsockname()[1]
    port_socket.close()

    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_trust = TrustStore(tmp_path / "client-trust.json")
    server_trust = TrustStore(tmp_path / "server-trust.json")
    client_trust.trust(server_identity.device_id, "server", server_identity.public_key)
    server_trust.trust(client_identity.device_id, "client", client_identity.public_key)

    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
        protocol_version=3,
        hostname="server",
    )
    server_history = TransferHistoryStore(tmp_path / "server-history.db")
    server_holder = []

    def cancel_it(request) -> None:
        server_holder[0].cancel_incoming_request(
            request.transfer_id, "Cancelled by user"
        )

    server = SecureTransfer(
        transfer_port=port,
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_trust,
        legacy_mode=False,
        history_store=server_history,
        on_incoming_request=cancel_it,
    )
    server_holder.append(server)

    client = SecureTransfer(
        transfer_port=port,
        identity=client_identity,
        trust_store=client_trust,
        peer_resolver=lambda _peer: peer,
        legacy_mode=False,
    )

    source = tmp_path / "cancelled.bin"
    source.write_bytes(b"content")

    server.start_server()
    time.sleep(0.05)
    try:
        transfer_id = client.send_file("127.0.0.1", str(source))
        deadline = time.time() + 5
        while time.time() < deadline:
            record = server_history.get_transfer(transfer_id)
            files = server_history.get_files(transfer_id)
            if (
                record
                and record.status == "cancelled"
                and files
                and files[0].status == "cancelled"
            ):
                break
            time.sleep(0.02)

        record = server_history.get_transfer(transfer_id)
        assert record is not None
        assert record.status == "cancelled"
        files = server_history.get_files(transfer_id)
        assert len(files) == 1
        assert files[0].status == "cancelled"
    finally:
        server.stop_server()
