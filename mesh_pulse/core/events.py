"""Lightweight application event boundary for core worker notifications."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from mesh_pulse.core.inbox import IncomingTransferRequest
from mesh_pulse.core.transfer_models import TransferInfo
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


@dataclass(frozen=True)
class IncomingTransferOffered:
    request: IncomingTransferRequest


@dataclass(frozen=True)
class TransferUpdated:
    transfers: tuple[TransferInfo, ...]


@dataclass(frozen=True)
class TransferCompleted:
    transfer: TransferInfo


@dataclass(frozen=True)
class TransferFailed:
    transfer: TransferInfo


TransferEvent = (
    IncomingTransferOffered | TransferUpdated | TransferCompleted | TransferFailed
)


class EventPublisher:
    """Thread-safe in-process publisher; subscribers choose thread dispatch."""

    def __init__(self) -> None:
        self._subscribers: list[Callable[[TransferEvent], None]] = []
        self._lock = threading.RLock()

    def subscribe(self, callback: Callable[[TransferEvent], None]) -> None:
        with self._lock:
            if callback not in self._subscribers:
                self._subscribers.append(callback)

    def publish(self, event: TransferEvent) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except (RuntimeError, TypeError, ValueError) as error:
                log.error("Transfer event subscriber failed: %s", error)
