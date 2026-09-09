"""Domain models shared by transfer networking, persistence, and UI."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum


class TransferDirection(Enum):
    SEND = "send"
    RECV = "recv"


class TransferStatus(Enum):
    PENDING = "pending"
    PENDING_APPROVAL = "pending_approval"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    ACTIVE = "active"
    INTERRUPTED = "interrupted"
    RESUMING = "resuming"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_TRANSFER_STATUSES = frozenset(
    {
        TransferStatus.COMPLETE,
        TransferStatus.FAILED,
        TransferStatus.REJECTED,
        TransferStatus.CANCELLED,
    }
)


@dataclass
class TransferInfo:
    """Thread-shared runtime state for one file in a transfer session."""

    filename: str
    filesize: int
    direction: TransferDirection
    peer_ip: str
    status: TransferStatus = TransferStatus.PENDING
    bytes_transferred: int = 0
    started_at: float = field(default_factory=time.time)
    error: str | None = None
    retry_count: int = 0
    peer_device_id: str | None = None
    transfer_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    file_id: str | None = None
    resume_offset: int = 0
    bytes_transferred_this_attempt: int = 0
    completed_at: float | None = None
    message: str | None = None
    sha256: str | None = None
    final_path: str | None = None

    @property
    def progress(self) -> float:
        if self.filesize == 0:
            return 100.0
        return min(100.0, max(0.0, self.bytes_transferred / self.filesize * 100))

    @property
    def elapsed(self) -> float:
        return max(0.0, time.time() - self.started_at)

    @property
    def speed_mbps(self) -> float:
        if self.elapsed == 0:
            return 0.0
        return (self.bytes_transferred_this_attempt / (1024 * 1024)) / self.elapsed

    def to_dict(self) -> dict:
        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "direction": self.direction.value,
            "peer_ip": self.peer_ip,
            "status": self.status.value,
            "progress": round(self.progress, 1),
            "speed_mbps": round(self.speed_mbps, 2),
            "retry_count": self.retry_count,
            "peer_device_id": self.peer_device_id,
            "transfer_id": self.transfer_id,
            "resume_offset": self.resume_offset,
        }
