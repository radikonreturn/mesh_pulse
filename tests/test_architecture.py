"""Architecture boundaries, lifecycle invariants, and resource cleanup."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from mesh_pulse.core.events import EventPublisher, TransferUpdated
from mesh_pulse.core.inbox import (
    InboxCapacityError,
    IncomingFile,
    IncomingRequestManager,
    IncomingTransferRequest,
)
from mesh_pulse.core.transfer import FileServer
from mesh_pulse.core.transfer_lifecycle import (
    InvalidTransferTransition,
    set_status,
)
from mesh_pulse.core.transfer_models import (
    TransferDirection,
    TransferInfo,
    TransferStatus,
)
from mesh_pulse.utils.config import validate_port, validate_timeout


def _info(status: TransferStatus = TransferStatus.PENDING) -> TransferInfo:
    return TransferInfo("file.bin", 10, TransferDirection.SEND, "127.0.0.1", status)


def _request(transfer_id: str) -> IncomingTransferRequest:
    return IncomingTransferRequest(
        transfer_id=transfer_id,
        peer_device_id="mp-12345678",
        peer_ip="127.0.0.1",
        peer_name="peer",
        files=(IncomingFile("file-0", "file.bin", 1, "a" * 64),),
        total_size=1,
        message=None,
        received_at=time.time(),
    )


def test_terminal_complete_cannot_regress():
    info = _info(TransferStatus.ACTIVE)
    set_status(info, TransferStatus.COMPLETE)
    with pytest.raises(InvalidTransferTransition):
        set_status(info, TransferStatus.ACTIVE)
    assert info.status == TransferStatus.COMPLETE


def test_interrupted_resume_active_complete_flow():
    info = _info(TransferStatus.ACTIVE)
    for status in (
        TransferStatus.INTERRUPTED,
        TransferStatus.RESUMING,
        TransferStatus.ACTIVE,
        TransferStatus.COMPLETE,
    ):
        set_status(info, status)
    assert info.status == TransferStatus.COMPLETE
    assert info.completed_at is not None


def test_event_publisher_is_framework_neutral():
    received = []
    publisher = EventPublisher()
    publisher.subscribe(received.append)
    event = TransferUpdated((_info(),))
    publisher.publish(event)
    assert received == [event]
    core_sources = Path("mesh_pulse/core").glob("*.py")
    assert all(
        "textual" not in path.read_text(encoding="utf-8") for path in core_sources
    )


def test_pending_request_limit_is_bounded():
    manager = IncomingRequestManager(max_pending=1)
    manager.publish(_request("a" * 32))
    with pytest.raises(InboxCapacityError):
        manager.publish(_request("b" * 32))


@pytest.mark.parametrize("value", [0, -1, 65536, True, "bad"])
def test_invalid_ports_rejected(value):
    with pytest.raises((TypeError, ValueError)):
        validate_port(value, "port")


@pytest.mark.parametrize("value", [0, -1, 3601, True, "bad"])
def test_invalid_timeouts_rejected(value):
    with pytest.raises((TypeError, ValueError)):
        validate_timeout(value, "timeout")


def test_server_shutdown_closes_active_connection(tmp_path):
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    server = FileServer(port=port, receive_dir=str(tmp_path))
    server.start()
    time.sleep(0.05)
    client = socket.create_connection(("127.0.0.1", port), timeout=1)
    deadline = time.time() + 1
    while time.time() < deadline and not server.active_session_count:
        time.sleep(0.01)
    server.shutdown()
    server.join(timeout=2)
    assert not server.is_alive()
    assert server.active_session_count == 0
    client.close()
