"""Persistent Ed25519 device identity for Mesh-Pulse installations."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from platformdirs import user_config_path

from mesh_pulse.utils.logger import get_logger

log = get_logger(__name__)

IDENTITY_VERSION = 1
DEVICE_ID_PATTERN = re.compile(r"^mp-[0-9a-f]{8}$")


def default_app_dir() -> Path:
    """Return the cross-platform per-user Mesh-Pulse config directory."""
    return user_config_path("mesh-pulse", appauthor=False)


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key as canonical base64."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def decode_public_key(value: str) -> Ed25519PublicKey:
    """Decode and validate a canonical base64 Ed25519 public key."""
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("Invalid Ed25519 public key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("Invalid Ed25519 public key") from error
    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 public key length")
    return Ed25519PublicKey.from_public_bytes(raw)


def device_id_from_public_key(public_key: str) -> str:
    """Derive a stable non-secret device identifier from a public key."""
    raw = base64.b64decode(public_key, validate=True)
    return f"mp-{hashlib.sha256(raw).hexdigest()[:8]}"


def fingerprint_from_public_key(public_key: str) -> str:
    """Create a deterministic human-verifiable public-key fingerprint."""
    raw = base64.b64decode(public_key, validate=True)
    digest = hashlib.sha256(raw).hexdigest()[:16].upper()
    return " ".join(digest[index : index + 4] for index in range(0, 16, 4))


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Atomically replace a small identity file with restrictive permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as file_handle:
            file_handle.write(data)
            file_handle.flush()
            os.fsync(file_handle.fileno())
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
    except OSError:
        temporary_path.unlink(missing_ok=True)
        raise


@dataclass(frozen=True)
class DeviceIdentity:
    """A loaded signing identity; private key material is never represented."""

    device_id: str
    public_key: str
    fingerprint: str
    created_at: float
    _private_key: Ed25519PrivateKey = field(repr=False, compare=False)
    directory: Path = field(repr=False, compare=False)

    @classmethod
    def load_or_create(cls, directory: str | Path | None = None) -> DeviceIdentity:
        """Load the persistent identity, creating it on first startup."""
        app_dir = Path(directory) if directory is not None else default_app_dir()
        key_path = app_dir / "identity.key"
        metadata_path = app_dir / "identity.json"

        private_key = cls._load_private_key(key_path)
        if private_key is None:
            private_key = Ed25519PrivateKey.generate()
            raw_private = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            _atomic_write(key_path, base64.b64encode(raw_private) + b"\n", 0o600)

        public_key = encode_public_key(private_key.public_key())
        stored_metadata = cls._load_metadata(metadata_path)
        stored_device_id = stored_metadata.get("device_id")
        device_id = (
            stored_device_id
            if isinstance(stored_device_id, str)
            and DEVICE_ID_PATTERN.fullmatch(stored_device_id)
            else device_id_from_public_key(public_key)
        )
        fingerprint = fingerprint_from_public_key(public_key)
        stored_created_at = stored_metadata.get("created_at")
        try:
            created_at = float(stored_created_at)
        except (ValueError, TypeError):
            created_at = time.time()
        metadata = {
            "version": IDENTITY_VERSION,
            "device_id": device_id,
            "public_key": public_key,
            "fingerprint": fingerprint,
            "created_at": created_at,
        }
        _atomic_write(
            metadata_path,
            (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            0o600,
        )
        return cls(
            device_id=device_id,
            public_key=public_key,
            fingerprint=fingerprint,
            created_at=created_at,
            _private_key=private_key,
            directory=app_dir,
        )

    @staticmethod
    def _load_private_key(path: Path) -> Ed25519PrivateKey | None:
        if not path.is_file():
            return None
        try:
            raw = base64.b64decode(path.read_bytes().strip(), validate=True)
            if len(raw) != 32:
                raise ValueError("unexpected private key length")
            key = Ed25519PrivateKey.from_private_bytes(raw)
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
            return key
        except (OSError, ValueError, base64.binascii.Error) as error:
            log.warning(
                "Device identity key is unreadable; generating a new identity: %s",
                error,
            )
            return None

    @staticmethod
    def _load_metadata(path: Path) -> dict:
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def sign(self, data: bytes) -> bytes:
        """Sign handshake transcript data with the persistent identity."""
        return self._private_key.sign(data)

    def verify(self, signature: bytes, data: bytes) -> bool:
        """Verify a signature made by this identity's public key."""
        try:
            self._private_key.public_key().verify(signature, data)
        except InvalidSignature:
            return False
        return True
