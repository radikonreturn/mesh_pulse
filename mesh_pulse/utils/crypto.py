"""Encryption utilities for secure file transfer.

Primary backend (v2):
    AES-256-GCM — 256-bit keys, authenticated encryption, unique nonce per chunk.
    Used by FileServer / FileClient for all data on the wire.

Legacy backend (v1):
    Fernet (AES-128-CBC + HMAC-SHA256) — kept for backwards-compat in tests only.
    NOT used in the production transfer path as of v2.

Key derivation:
    Shared passphrases are converted to 32-byte AES keys via PBKDF2-HMAC-SHA256
    with a fixed application salt so that peers sharing the same passphrase always
    derive the same key without exchanging salt over the network.
"""

from __future__ import annotations

import os
import stat
import struct

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from mesh_pulse.utils.config import KEY_FILE, PBKDF2_ITERATIONS, NONCE_SIZE


# ─── Application-level fixed salt ─────────────────────────────────
# Using a fixed salt means both ends derive the same key from the same
# passphrase without needing to exchange salt over the wire.
# The passphrase itself provides the entropy; the salt is a domain separator.
_APP_SALT = b"mesh-pulse-v2-aes256gcm-salt-2026"


# ─── Primary: AES-256-GCM key derivation ──────────────────────────


def derive_session_key(passphrase: str) -> bytes:
    """Derive a 32-byte AES-256 key from a passphrase via PBKDF2-HMAC-SHA256.

    Both sender and receiver must call this with the same passphrase to obtain
    the same key.  Uses a fixed application salt so no salt exchange is needed.

    Args:
        passphrase: User-supplied passphrase string.

    Returns:
        32-byte raw key suitable for AES-256-GCM.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_APP_SALT,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_chunk(data: bytes, key: bytes) -> bytes:
    """Encrypt a data chunk with AES-256-GCM.

    Output format: [12-byte nonce][ciphertext + 16-byte auth tag]

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte AES-256 key.

    Returns:
        Encrypted payload (nonce + ciphertext + auth tag).
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_chunk(payload: bytes, key: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted chunk.

    Args:
        payload: Encrypted payload (nonce + ciphertext + auth tag).
        key: 32-byte AES-256 key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails (tampering/wrong key).
    """
    if len(payload) < NONCE_SIZE:
        raise ValueError(f"Payload too short: {len(payload)} bytes")
    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─── Framing (shared, used by both send and receive) ──────────────


def pack_frame(data: bytes) -> bytes:
    """Pack data with a 4-byte big-endian length prefix.

    Args:
        data: Raw bytes to frame.

    Returns:
        Length-prefixed frame: [4-byte length][data].
    """
    return struct.pack(">I", len(data)) + data


def unpack_frame(sock, max_size: int = 64 * 1024 * 1024) -> bytes:
    """Read a length-prefixed frame from a socket.

    Args:
        sock: Connected socket to read from.
        max_size: Maximum allowed frame size in bytes (default 64 MB).

    Returns:
        The framed data bytes.

    Raises:
        ConnectionError: If the peer disconnects mid-frame.
        ValueError: If the frame size exceeds max_size.
    """
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        raise ConnectionError("Connection closed while reading frame length")
    length = struct.unpack(">I", raw_len)[0]

    if length > max_size:
        raise ValueError(f"Frame size {length} exceeds maximum allowed {max_size}")

    data = _recv_exact(sock, length)
    if not data:
        raise ConnectionError("Connection closed while reading frame data")
    return data


def _recv_exact(sock, n: int) -> bytes:
    """Receive exactly n bytes from a socket.

    Args:
        sock: Connected socket.
        n: Number of bytes to receive.

    Returns:
        Exactly n bytes, or empty bytes if connection was closed.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)


# ─── Legacy: Fernet (AES-128-CBC) — kept for test compat only ─────
# These functions are NOT used in the v2 production transfer path.


def load_or_generate_key(path: str = KEY_FILE) -> bytes:
    """Load a Fernet key from disk, or generate and save a new one.

    Legacy helper used by older test fixtures.  Production code uses
    derive_session_key() instead.

    Args:
        path: Filesystem path to the key file.

    Returns:
        A valid Fernet key (44 url-safe base64 bytes).
    """
    if os.path.isfile(path):
        with open(path, "rb") as f:
            key = f.read().strip()
        try:
            Fernet(key)
            return key
        except Exception:
            pass  # regenerate if corrupted

    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(key)
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return key


def get_fernet(key: bytes | None = None) -> Fernet:
    """Return a Fernet instance.  Legacy — not used in v2 transfers."""
    if key is None:
        key = load_or_generate_key()
    return Fernet(key)


def fernet_encrypt(data: bytes, key: bytes | None = None) -> bytes:
    """Encrypt data using Fernet (AES-128-CBC).  Legacy — tests only."""
    return get_fernet(key).encrypt(data)


def fernet_decrypt(token: bytes, key: bytes | None = None) -> bytes:
    """Decrypt a Fernet token.  Legacy — tests only."""
    return get_fernet(key).decrypt(token)


# ─── Legacy: PBKDF2 with random salt ──────────────────────────────
# Kept so existing test_crypto.py / test_crypto_dos.py still pass.


def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from a passphrase using PBKDF2-HMAC-SHA256.

    Legacy — uses a random salt (requires salt exchange).  New code should
    use derive_session_key() which uses the fixed application salt.

    Args:
        passphrase: User-supplied passphrase string.
        salt: Optional salt bytes. Generated randomly if not provided.

    Returns:
        Tuple of (derived_key, salt).
    """
    from mesh_pulse.utils.config import SALT_SIZE

    if salt is None:
        salt = os.urandom(SALT_SIZE)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    return key, salt
