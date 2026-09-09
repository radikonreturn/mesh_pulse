"""Protocol-v3 incoming transfer approval tests."""

from __future__ import annotations

import asyncio
import hashlib
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from rich.console import Console
from textual.app import App

from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.inbox import (
    IncomingFile,
    IncomingRequestManager,
    IncomingRequestStatus,
    IncomingTransferRequest,
)
from mesh_pulse.core.session import ProtocolError, client_handshake
from mesh_pulse.core.transfer import FileClient, FileServer, TransferStatus
from mesh_pulse.core.transfer_protocol import validate_offer
from mesh_pulse.core.trust import TrustStatus, TrustStore
from mesh_pulse.tui.screens.inbox import InboxScreen, format_request_detail


def _port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _trusted_pair(tmp_path):
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


def _wait_status(client: FileClient, statuses: set[TransferStatus]) -> TransferStatus:
    deadline = time.time() + 4
    while time.time() < deadline:
        records = client.get_transfers()
        if records and records[-1].status in statuses:
            return records[-1].status
        time.sleep(0.02)
    return client.get_transfers()[-1].status


def _request(transfer_id: str) -> IncomingTransferRequest:
    return IncomingTransferRequest(
        transfer_id=transfer_id,
        peer_device_id="mp-12345678",
        peer_ip="127.0.0.1",
        peer_name="peer",
        files=(IncomingFile("file-0", "file.bin", 3, "a" * 64),),
        total_size=3,
        message=None,
        received_at=time.time(),
    )


def _rejecting_manager() -> IncomingRequestManager:
    holder: list[IncomingRequestManager] = []

    def reject(request: IncomingTransferRequest) -> None:
        holder[0].reject_request(request.transfer_id)

    manager = IncomingRequestManager(reject)
    holder.append(manager)
    return manager


def test_request_manager_accept_reject_and_multiple_requests():
    manager = IncomingRequestManager()
    first = "1" * 32
    second = "2" * 32
    manager.publish(_request(first))
    manager.publish(_request(second))
    assert len(manager.get_pending_requests()) == 2
    assert manager.accept_request(first)
    assert manager.reject_request(second)
    assert manager.wait_for_decision(first, 0).status == IncomingRequestStatus.ACCEPTED
    assert manager.wait_for_decision(second, 0).status == IncomingRequestStatus.REJECTED
    assert manager.get_pending_requests() == []


def test_request_manager_timeout():
    manager = IncomingRequestManager()
    transfer_id = "3" * 32
    manager.publish(_request(transfer_id))
    result = manager.wait_for_decision(transfer_id, 0.01)
    assert result.status == IncomingRequestStatus.EXPIRED


def test_inbox_detail_formatting():
    console = Console(record=True, width=100)
    console.print(format_request_detail(_request("9" * 32), "ABCD 1234"))
    text = console.export_text()
    assert "peer" in text
    assert "file.bin" in text
    assert "ABCD 1234" in text


class _InboxApp(App):
    def __init__(self, manager: IncomingRequestManager, trust_store: TrustStore):
        super().__init__()
        self.manager = manager
        self.trust_store = trust_store

    def on_mount(self) -> None:
        transfer = SimpleNamespace(
            get_pending_requests=self.manager.get_pending_requests,
            get_incoming_request=self.manager.get_request,
            accept_request=self.manager.accept_request,
            reject_request=self.manager.reject_request,
        )
        self.push_screen(InboxScreen(transfer, self.trust_store))


def test_inbox_empty_state_and_accept_action(tmp_path):
    async def exercise() -> None:
        manager = IncomingRequestManager()
        app = _InboxApp(manager, TrustStore(tmp_path / "trust.json"))
        async with app.run_test() as pilot:
            await pilot.pause()
            screen = app.screen
            assert screen.query_one("#inbox-empty").display
            manager.publish(_request("8" * 32))
            screen.refresh_requests()
            assert not screen.query_one("#inbox-empty").display
            screen.action_accept()
            assert (
                manager.get_request("8" * 32).status == IncomingRequestStatus.ACCEPTED
            )

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "change",
    [
        {"transfer_id": "bad"},
        {"count": 2},
        {"total_size": 4},
        {"files": [{"file_id": "../x", "name": "x", "size": 3, "sha256": "a" * 64}]},
        {
            "files": [
                {"file_id": "file-0", "name": "../x", "size": 3, "sha256": "a" * 64}
            ]
        },
    ],
)
def test_malformed_offer_rejected(change):
    offer = {
        "type": "transfer_offer",
        "version": 3,
        "transfer_id": "4" * 32,
        "count": 1,
        "total_size": 3,
        "files": [{"file_id": "file-0", "name": "x", "size": 3, "sha256": "a" * 64}],
    }
    offer.update(change)
    with pytest.raises(ProtocolError):
        validate_offer(offer)


def test_v3_offer_accepted_and_payload_waits_for_approval(tmp_path):
    client_id, server_id, client_store, server_store, peer = _trusted_pair(tmp_path)
    manager = IncomingRequestManager()
    port = _port()
    receive_dir = tmp_path / "received"
    source = tmp_path / "payload.bin"
    source.write_bytes(b"payload" * 2048)
    server = FileServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_id,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
        approval_timeout=2,
    )
    client = FileClient(
        port=port,
        identity=client_id,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
        approval_timeout=2,
    )
    server.start()
    time.sleep(0.1)
    try:
        transfer_id = client.send_batch("127.0.0.1", [str(source)])
        deadline = time.time() + 2
        while time.time() < deadline and not manager.get_pending_requests():
            time.sleep(0.01)
        assert manager.get_request(transfer_id) is not None
        assert not (receive_dir / source.name).exists()
        assert manager.accept_request(transfer_id)
        assert (
            _wait_status(client, {TransferStatus.COMPLETE}) == TransferStatus.COMPLETE
        )
        assert (receive_dir / source.name).read_bytes() == source.read_bytes()
    finally:
        server.shutdown()


def test_v3_offer_rejected_and_timeout(tmp_path):
    client_id, server_id, client_store, server_store, peer = _trusted_pair(tmp_path)
    for decision, expected in (
        ("reject", TransferStatus.REJECTED),
        ("timeout", TransferStatus.FAILED),
    ):
        manager = (
            _rejecting_manager() if decision == "reject" else IncomingRequestManager()
        )
        port = _port()
        source = tmp_path / f"{decision}.bin"
        source.write_bytes(hashlib.sha256(decision.encode()).digest())
        server = FileServer(
            port=port,
            receive_dir=str(tmp_path / f"received-{decision}"),
            identity=server_id,
            trust_store=server_store,
            legacy_mode=False,
            incoming_manager=manager,
            approval_timeout=0.05,
        )
        client = FileClient(
            port=port,
            identity=client_id,
            trust_store=client_store,
            peer_resolver=lambda _ip: peer,
            legacy_mode=False,
            approval_timeout=1,
        )
        server.start()
        time.sleep(0.05)
        try:
            client.send("127.0.0.1", str(source))
            assert _wait_status(client, {expected}) == expected
            assert not (tmp_path / f"received-{decision}" / source.name).exists()
        finally:
            server.shutdown()


def test_untrusted_sender_cannot_create_inbox_request(tmp_path):
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_store = TrustStore(tmp_path / "client-trust.json")
    server_store = TrustStore(tmp_path / "server-trust.json")
    client_store.trust(server_identity.device_id, "server", server_identity.public_key)
    manager = IncomingRequestManager()
    server = FileServer(
        receive_dir=str(tmp_path / "received"),
        identity=server_identity,
        trust_store=server_store,
        legacy_mode=False,
        incoming_manager=manager,
    )
    sender, receiver = socket.socketpair()
    worker = threading.Thread(
        target=server._receive_session, args=(receiver, "127.0.0.1")
    )
    worker.start()
    try:
        trusted_server = client_store.get(server_identity.device_id)
        with pytest.raises(ConnectionError):
            client_handshake(sender, client_identity, trusted_server)
        worker.join(timeout=1)
        assert manager.get_pending_requests() == []
    finally:
        sender.close()
