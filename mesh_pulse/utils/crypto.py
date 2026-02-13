"""Encryption utilities for secure file transfer.

Provides two encryption backends:
    1. Fernet (AES-128-CBC) — simple, key auto-generated and persisted to disk
    2. AES-256-GCM (legacy) — stronger, PBKDF2 key derivation from passphrase

The Fernet backend is used by FileServer/FileClient.
The AESGCM backend is used by SecureTransfer (legacy facade).
"""

import os
import struct

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from mesh_pulse.utils.config import KEY_FILE, PBKDF2_ITERATIONS, SALT_SIZE, NONCE_SIZE


# ─── Fernet Key Management ─────────────────────────────────────────


def load_or_generate_key(path: str = KEY_FILE) -> bytes:
    """Load a Fernet key from disk, or generate and save a new one.

    Args:
        path: Filesystem path to the key file.

    Returns:
        A valid Fernet key (44 url-safe base64 bytes).
    """
    if os.path.isfile(path):
        with open(path, "rb") as f:
            key = f.read().strip()
        # Validate it's a proper Fernet key
        try:
            Fernet(key)
            return key
        except Exception:
            pass  # regenerate if corrupted

    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(key)
    return key


def get_fernet(key: bytes | None = None) -> Fernet:
    """Return a Fernet instance, auto-loading the key if needed.

    Args:
        key: Optional pre-loaded key bytes. If None, loads from KEY_FILE.

    Returns:
        Ready-to-use Fernet encryptor/decryptor.
    """
    if key is None:
        key = load_or_generate_key()
    return Fernet(key)


def fernet_encrypt(data: bytes, key: bytes | None = None) -> bytes:
    """Encrypt data using Fernet (AES-128-CBC + HMAC-SHA256).

    Args:
        data: Plaintext bytes.
        key: Optional Fernet key. Auto-loaded if None.

    Returns:
        Fernet token (ciphertext).
    """
    return get_fernet(key).encrypt(data)


def fernet_decrypt(token: bytes, key: bytes | None = None) -> bytes:
    """Decrypt a Fernet token.

    Args:
        token: Fernet-encrypted token bytes.
        key: Optional Fernet key. Auto-loaded if None.

    Returns:
        Decrypted plaintext bytes.
    """
    return get_fernet(key).decrypt(token)


# ─── AES-256-GCM (Legacy / SecureTransfer) ─────────────────────────


def derive_key(passphrase: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive a 256-bit key from a passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: User-supplied passphrase string.
        salt: Optional salt bytes. Generated randomly if not provided.

    Returns:
        Tuple of (derived_key, salt).
    """
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


def encrypt_chunk(data: bytes, key: bytes) -> bytes:
    """Encrypt a data chunk with AES-256-GCM.

    Output format: [12-byte nonce][ciphertext + 16-byte auth tag]

    Args:
        data: Plaintext bytes to encrypt.
        key: 32-byte AES key.

    Returns:
        Encrypted payload (nonce + ciphertext).
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_chunk(payload: bytes, key: bytes) -> bytes:
    """Decrypt an AES-256-GCM encrypted chunk.

    Args:
        payload: Encrypted payload (nonce + ciphertext).
        key: 32-byte AES key.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails.
    """
    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# ─── Framing (shared between both backends) ────────────────────────


def pack_frame(data: bytes) -> bytes:
    """Pack data with a 4-byte big-endian length prefix.

    Args:
        data: Raw bytes to frame.

    Returns:
        Length-prefixed frame.
    """
    return struct.pack(">I", len(data)) + data


def unpack_frame(sock, max_size: int = 1024 * 1024) -> bytes:
    """Read a length-prefixed frame from a socket.

    Args:
        sock: Connected socket to read from.
        max_size: Maximum allowed frame size in bytes (default 1MB).

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
        Exactly n bytes, or empty bytes if connection closed.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf.extend(chunk)
    return bytes(buf)
