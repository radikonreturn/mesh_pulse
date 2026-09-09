"""Small guarded lifecycle for transfer state changes."""

from __future__ import annotations

import time

from mesh_pulse.core.transfer_models import (
    TERMINAL_TRANSFER_STATUSES,
    TransferInfo,
    TransferStatus,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


class InvalidTransferTransition(ValueError):
    """A requested state transition violates transfer lifecycle invariants."""


_ALLOWED: dict[TransferStatus, frozenset[TransferStatus]] = {
    TransferStatus.PENDING: frozenset(
        {
            TransferStatus.PENDING_APPROVAL,
            TransferStatus.ACTIVE,
            TransferStatus.INTERRUPTED,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.PENDING_APPROVAL: frozenset(
        {
            TransferStatus.ACCEPTED,
            TransferStatus.REJECTED,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.ACCEPTED: frozenset(
        {
            TransferStatus.ACTIVE,
            TransferStatus.RESUMING,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.ACTIVE: frozenset(
        {
            TransferStatus.INTERRUPTED,
            TransferStatus.RESUMING,
            TransferStatus.COMPLETE,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.INTERRUPTED: frozenset(
        {
            TransferStatus.RESUMING,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
    TransferStatus.RESUMING: frozenset(
        {
            TransferStatus.ACTIVE,
            TransferStatus.INTERRUPTED,
            TransferStatus.COMPLETE,
            TransferStatus.FAILED,
            TransferStatus.CANCELLED,
        }
    ),
}


def set_status(
    info: TransferInfo,
    status: TransferStatus,
    *,
    error: str | None = None,
    force: bool = False,
) -> bool:
    """Apply a valid transition; return False for an idempotent assignment."""
    current = info.status
    if current == status:
        if error is not None:
            info.error = error
        return False
    if not force and status not in _ALLOWED.get(current, frozenset()):
        raise InvalidTransferTransition(f"{current.value} -> {status.value}")
    info.status = status
    info.error = error
    log.debug(
        "Transfer %s peer=%s state %s -> %s",
        info.transfer_id[:12],
        (info.peer_device_id or info.peer_ip)[:48],
        current.value,
        status.value,
    )
    if status in TERMINAL_TRANSFER_STATUSES:
        info.completed_at = time.time()
    return True


def is_terminal(status: TransferStatus) -> bool:
    return status in TERMINAL_TRANSFER_STATUSES
