"""Persistent trust decisions keyed by cryptographic device identity."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from mesh_pulse.core.identity import (
    DEVICE_ID_PATTERN,
    decode_public_key,
    default_app_dir,
    device_id_from_public_key,
    fingerprint_from_public_key,
)
from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)


class TrustStatus(Enum):
    """A local decision about a discovered cryptographic identity."""

    NEW = "new"
    TRUSTED = "trusted"
    REJECTED = "rejected"
    CHANGED = "changed"


@dataclass(frozen=True)
class TrustedDevice:
    """Persisted public information and local trust decision for a peer."""

    device_id: str
    hostname: str
    public_key: str
    fingerprint: str
    first_trusted_at: float
    last_seen_at: float
    status: str = TrustStatus.TRUSTED.value


class TrustStore:
    """Thread-safe JSON trust store with atomic persistence."""

    def __init__(self, path: str | Path | None = None):
        self.path = (
            Path(path)
            if path is not None
            else default_app_dir() / "trusted_devices.json"
        )
        self._lock = threading.RLock()
        self._devices: dict[str, TrustedDevice] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            devices = payload.get("devices", {})
            if not isinstance(devices, dict):
                raise TypeError("devices must be an object")
            loaded: dict[str, TrustedDevice] = {}
            for device_id, record in devices.items():
                if not isinstance(record, dict) or record.get("device_id") != device_id:
                    continue
                candidate = TrustedDevice(**record)
                self._validate(candidate.device_id, candidate.public_key)
                loaded[device_id] = candidate
            self._devices = loaded
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
            log.warning("Ignoring invalid trust store %s: %s", self.path, error)
            self._devices = {}

    @staticmethod
    def _validate(device_id: str, public_key: str) -> None:
        """Validate that a device ID is cryptographically bound to its public key."""
        decode_public_key(public_key)

        if not isinstance(device_id, str) or not DEVICE_ID_PATTERN.fullmatch(device_id):
            raise ValueError("Invalid device ID")

        expected_device_id = device_id_from_public_key(public_key)

        if device_id != expected_device_id:
            raise ValueError("Device ID does not match the supplied public key")

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "devices": {
                device_id: asdict(record)
                for device_id, record in sorted(self._devices.items())
            },
        }
        data = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent
        )
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as file_handle:
                file_handle.write(data)
                file_handle.flush()
                os.fsync(file_handle.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, self.path)
        except OSError:
            temporary_path.unlink(missing_ok=True)
            raise

    def get(self, device_id: str) -> TrustedDevice | None:
        """Return a persisted record by stable device ID."""
        with self._lock:
            return self._devices.get(device_id)

    def all(self) -> list[TrustedDevice]:
        """Return a snapshot of all persisted decisions."""
        with self._lock:
            return list(self._devices.values())

    def assess(self, device_id: str | None, public_key: str | None) -> TrustStatus:
        """Assess advertised identity without changing trust."""
        if not device_id or not public_key:
            return TrustStatus.NEW
        with self._lock:
            record = self._devices.get(device_id)
            if record is None:
                return TrustStatus.NEW
            if record.public_key != public_key:
                return TrustStatus.CHANGED
            return TrustStatus(record.status)

    def trust(
        self,
        device_id: str,
        hostname: str,
        public_key: str,
        *,
        last_seen_at: float | None = None,
    ) -> TrustedDevice:
        """Persist explicit trust for a validated public identity."""
        self._validate(device_id, public_key)
        now = time.time()
        with self._lock:
            existing = self._devices.get(device_id)
            record = TrustedDevice(
                device_id=device_id,
                hostname=hostname[:255],
                public_key=public_key,
                fingerprint=fingerprint_from_public_key(public_key),
                first_trusted_at=(existing.first_trusted_at if existing else now),
                last_seen_at=last_seen_at or now,
                status=TrustStatus.TRUSTED.value,
            )
            self._devices[device_id] = record
            self._save()
            return record

    def reject(
        self,
        device_id: str,
        hostname: str,
        public_key: str,
    ) -> TrustedDevice:
        """Persist an explicit rejection for a validated public identity."""
        self._validate(device_id, public_key)
        now = time.time()
        with self._lock:
            record = TrustedDevice(
                device_id=device_id,
                hostname=hostname[:255],
                public_key=public_key,
                fingerprint=fingerprint_from_public_key(public_key),
                first_trusted_at=now,
                last_seen_at=now,
                status=TrustStatus.REJECTED.value,
            )
            self._devices[device_id] = record
            self._save()
            return record

    def untrust(self, device_id: str) -> bool:
        """Remove a local trust/rejection decision."""
        with self._lock:
            existed = self._devices.pop(device_id, None) is not None
            if existed:
                self._save()
            return existed

    def update_last_seen(self, device_id: str, timestamp: float) -> None:
        """Update a known unchanged device's last-seen timestamp."""
        with self._lock:
            record = self._devices.get(device_id)
            if record is None:
                return
            if timestamp - record.last_seen_at < 30:
                return
            self._devices[device_id] = TrustedDevice(
                **{**asdict(record), "last_seen_at": timestamp}
            )
            self._save()
