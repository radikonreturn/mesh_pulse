"""Thread-safe incoming transfer approval state."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum

from mesh_pulse.utils.config import MAX_PENDING_TRANSFER_REQUESTS


class InboxCapacityError(RuntimeError):
    """The bounded incoming approval queue is full."""


class IncomingRequestStatus(Enum):
    """Lifecycle of an authenticated incoming transfer offer."""

    PENDING_APPROVAL = "pending_approval"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class IncomingFile:
    """Validated metadata for one offered file."""

    file_id: str
    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class IncomingTransferRequest:
    """A transfer offer published after v3 peer authentication."""

    transfer_id: str
    peer_device_id: str
    peer_ip: str
    peer_name: str | None
    files: tuple[IncomingFile, ...]
    total_size: int
    message: str | None
    received_at: float
    status: IncomingRequestStatus = IncomingRequestStatus.PENDING_APPROVAL
    reason: str | None = None


@dataclass
class _PendingDecision:
    request: IncomingTransferRequest
    event: threading.Event


class IncomingRequestManager:
    """Own pending offers and coordinate UI decisions with session workers."""

    def __init__(
        self,
        on_request: Callable[[IncomingTransferRequest], None] | None = None,
        on_decision: Callable[[IncomingTransferRequest], None] | None = None,
        max_pending: int = MAX_PENDING_TRANSFER_REQUESTS,
    ) -> None:
        self._entries: dict[str, _PendingDecision] = {}
        self._lock = threading.RLock()
        self._on_request = on_request
        self._on_decision = on_decision
        if max_pending <= 0:
            raise ValueError("max_pending must be positive")
        self._max_pending = max_pending

    def publish(self, request: IncomingTransferRequest) -> None:
        """Publish a newly authenticated request without exposing mutable state."""
        with self._lock:
            existing = self._entries.get(request.transfer_id)
            if existing is not None:
                prior = existing.request
                same_offer = (
                    prior.peer_device_id == request.peer_device_id
                    and prior.files == request.files
                    and prior.total_size == request.total_size
                    and prior.message == request.message
                )
                if not same_offer:
                    raise ValueError("Transfer ID metadata changed")
                if prior.status == IncomingRequestStatus.ACCEPTED:
                    resumed = replace(request, status=IncomingRequestStatus.ACCEPTED)
                    event = threading.Event()
                    event.set()
                    self._entries[request.transfer_id] = _PendingDecision(
                        request=resumed, event=event
                    )
                    return
                raise ValueError("Transfer request already exists")
            pending_count = sum(
                entry.request.status == IncomingRequestStatus.PENDING_APPROVAL
                for entry in self._entries.values()
            )
            if pending_count >= self._max_pending:
                raise InboxCapacityError("Incoming transfer inbox is full")
            self._entries[request.transfer_id] = _PendingDecision(
                request=request,
                event=threading.Event(),
            )
        if self._on_request is not None:
            self._on_request(request)

    def get_pending_requests(self) -> list[IncomingTransferRequest]:
        """Return immutable snapshots ordered newest first."""
        with self._lock:
            requests = [
                entry.request
                for entry in self._entries.values()
                if entry.request.status == IncomingRequestStatus.PENDING_APPROVAL
            ]
        return sorted(requests, key=lambda item: item.received_at, reverse=True)

    def get_request(self, transfer_id: str) -> IncomingTransferRequest | None:
        with self._lock:
            entry = self._entries.get(transfer_id)
            return entry.request if entry is not None else None

    def accept_request(self, transfer_id: str) -> bool:
        return self._decide(transfer_id, IncomingRequestStatus.ACCEPTED, None)

    def reject_request(
        self, transfer_id: str, reason: str = "Rejected by user"
    ) -> bool:
        return self._decide(transfer_id, IncomingRequestStatus.REJECTED, reason)

    def cancel_request(
        self, transfer_id: str, reason: str = "Cancelled by peer"
    ) -> bool:
        return self._decide(transfer_id, IncomingRequestStatus.CANCELLED, reason)

    def wait_for_decision(
        self, transfer_id: str, timeout: float
    ) -> IncomingTransferRequest:
        """Wait without busy-looping and expire an undecided request."""
        with self._lock:
            entry = self._entries.get(transfer_id)
            if entry is None:
                raise KeyError(transfer_id)
            event = entry.event
        if not event.wait(timeout):
            self._decide(
                transfer_id,
                IncomingRequestStatus.EXPIRED,
                "Transfer request expired",
            )
        request = self.get_request(transfer_id)
        if request is None:  # pragma: no cover - guarded by retained entries
            raise KeyError(transfer_id)
        return request

    def prune(self, older_than: float = 3600.0) -> None:
        """Remove old terminal requests while retaining current inbox state."""
        cutoff = time.time() - older_than
        with self._lock:
            self._entries = {
                transfer_id: entry
                for transfer_id, entry in self._entries.items()
                if entry.request.status == IncomingRequestStatus.PENDING_APPROVAL
                or entry.request.received_at >= cutoff
            }

    def cancel_all(self, reason: str = "Receiver is shutting down") -> None:
        """Wake all pending session workers during service shutdown."""
        with self._lock:
            pending_ids = [
                transfer_id
                for transfer_id, entry in self._entries.items()
                if entry.request.status == IncomingRequestStatus.PENDING_APPROVAL
            ]
        for transfer_id in pending_ids:
            self.cancel_request(transfer_id, reason)

    def _decide(
        self,
        transfer_id: str,
        status: IncomingRequestStatus,
        reason: str | None,
    ) -> bool:
        with self._lock:
            entry = self._entries.get(transfer_id)
            if (
                entry is None
                or entry.request.status != IncomingRequestStatus.PENDING_APPROVAL
            ):
                return False
            entry.request = replace(entry.request, status=status, reason=reason)
            decided = entry.request
            entry.event.set()
        if decided is not None and self._on_decision is not None:
            self._on_decision(decided)
        return True
