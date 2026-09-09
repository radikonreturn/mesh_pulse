"""Authenticated protocol-v3 session handshake.

Persistent Ed25519 identities authenticate fresh ephemeral X25519 keys. The
resulting shared secret is expanded with HKDF-SHA256 and a transcript-bound
context into an independent AES-256-GCM key for each TCP connection.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from mesh_pulse.core.identity import (
    DEVICE_ID_PATTERN,
    DeviceIdentity,
    decode_public_key,
)
from mesh_pulse.core.trust import TrustedDevice, TrustStatus, TrustStore
from mesh_pulse.utils.crypto import pack_frame, unpack_frame

PROTOCOL_VERSION = 3
MAX_HANDSHAKE_SIZE = 8192
NONCE_BYTES = 32
_DOMAIN = b"mesh-pulse-v3-authenticated-handshake\x00"


class ProtocolError(ConnectionError):
    """A peer sent a malformed or incompatible protocol message."""


class AuthenticationError(ConnectionError):
    """A peer could not be authenticated against the local trust store."""


@dataclass(frozen=True)
class AuthenticatedSession:
    """Result of a successful v3 key agreement."""

    key: bytes
    peer_device_id: str


def _b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64decode(value: object, *, expected_length: int, field: str) -> bytes:
    if not isinstance(value, str) or len(value) > 256:
        raise ProtocolError(f"Invalid {field}")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ProtocolError(f"Invalid {field}") from error
    if len(raw) != expected_length:
        raise ProtocolError(f"Invalid {field} length")
    return raw


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _signed_bytes(payload: dict) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "signature"}
    return _DOMAIN + _canonical(unsigned)


def _ephemeral_public(private_key: X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _create_hello(
    role: str,
    identity: DeviceIdentity,
    ephemeral_key: bytes,
    nonce: bytes,
    *,
    peer_hello_hash: str | None = None,
) -> dict:
    payload = {
        "type": "hello",
        "protocol": PROTOCOL_VERSION,
        "role": role,
        "device_id": identity.device_id,
        "identity_key": identity.public_key,
        "ephemeral_key": _b64encode(ephemeral_key),
        "nonce": _b64encode(nonce),
    }
    if peer_hello_hash is not None:
        payload["peer_hello_hash"] = peer_hello_hash
    payload["signature"] = _b64encode(identity.sign(_signed_bytes(payload)))
    return payload


def _validate_hello(payload: object, expected_role: str) -> tuple[dict, bytes, bytes]:
    if not isinstance(payload, dict):
        raise ProtocolError("Handshake must be a JSON object")
    if payload.get("type") != "hello":
        raise ProtocolError("Invalid handshake type")
    if payload.get("protocol") != PROTOCOL_VERSION:
        raise ProtocolError("Protocol version mismatch")
    if payload.get("role") != expected_role:
        raise ProtocolError("Invalid handshake role")

    device_id = payload.get("device_id")
    identity_key = payload.get("identity_key")
    if (
        not isinstance(device_id, str)
        or not DEVICE_ID_PATTERN.fullmatch(device_id)
        or not isinstance(identity_key, str)
    ):
        raise ProtocolError("Missing peer identity")
    try:
        public_key = decode_public_key(identity_key)
    except ValueError as error:
        raise ProtocolError("Invalid peer identity key") from error

    ephemeral = _b64decode(
        payload.get("ephemeral_key"), expected_length=32, field="ephemeral key"
    )
    nonce = _b64decode(payload.get("nonce"), expected_length=NONCE_BYTES, field="nonce")
    signature = _b64decode(
        payload.get("signature"), expected_length=64, field="signature"
    )
    try:
        public_key.verify(signature, _signed_bytes(payload))
    except InvalidSignature as error:
        raise AuthenticationError("Signature verification failed") from error
    return payload, ephemeral, nonce


def _send_json(sock, payload: dict) -> None:
    encoded = _canonical(payload)
    if len(encoded) > MAX_HANDSHAKE_SIZE:
        raise ProtocolError("Handshake frame is too large")
    sock.sendall(pack_frame(encoded))


def _receive_json(sock) -> dict:
    raw = unpack_frame(sock, max_size=MAX_HANDSHAKE_SIZE)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ProtocolError("Invalid pairing response") from error
    if not isinstance(payload, dict):
        raise ProtocolError("Invalid pairing response")
    return payload


def _derive_key(
    private_key: X25519PrivateKey,
    remote_ephemeral: bytes,
    client_hello: dict,
    server_hello: dict,
    client_nonce: bytes,
    server_nonce: bytes,
) -> bytes:
    try:
        shared_secret = private_key.exchange(
            X25519PublicKey.from_public_bytes(remote_ephemeral)
        )
    except ValueError as error:
        raise ProtocolError("Invalid ephemeral key") from error
    transcript = hashlib.sha256(
        _canonical(client_hello) + b"\x00" + _canonical(server_hello)
    ).digest()
    salt = hashlib.sha256(client_nonce + server_nonce).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=_DOMAIN + transcript,
    ).derive(shared_secret)


def client_handshake(
    sock,
    identity: DeviceIdentity,
    trusted_peer: TrustedDevice,
) -> AuthenticatedSession:
    """Authenticate a trusted server and derive a fresh session key."""
    if trusted_peer.status != TrustStatus.TRUSTED.value:
        raise AuthenticationError("Peer is not trusted")
    ephemeral_private = X25519PrivateKey.generate()
    client_nonce = os.urandom(NONCE_BYTES)
    client_hello = _create_hello(
        "client", identity, _ephemeral_public(ephemeral_private), client_nonce
    )
    _send_json(sock, client_hello)

    server_hello, server_ephemeral, server_nonce = _validate_hello(
        _receive_json(sock), "server"
    )
    if (
        server_hello["device_id"] != trusted_peer.device_id
        or server_hello["identity_key"] != trusted_peer.public_key
    ):
        raise AuthenticationError("Wrong peer identity")
    expected_hash = hashlib.sha256(_canonical(client_hello)).hexdigest()
    if server_hello.get("peer_hello_hash") != expected_hash:
        raise AuthenticationError("Handshake transcript mismatch")

    key = _derive_key(
        ephemeral_private,
        server_ephemeral,
        client_hello,
        server_hello,
        client_nonce,
        server_nonce,
    )
    return AuthenticatedSession(key, trusted_peer.device_id)


def server_handshake(
    sock,
    identity: DeviceIdentity,
    trust_store: TrustStore,
) -> AuthenticatedSession:
    """Authenticate a trusted client and derive a fresh session key."""
    client_hello, client_ephemeral, client_nonce = _validate_hello(
        _receive_json(sock), "client"
    )
    device_id = client_hello["device_id"]
    identity_key = client_hello["identity_key"]
    if trust_store.assess(device_id, identity_key) != TrustStatus.TRUSTED:
        raise AuthenticationError("Untrusted peer")

    ephemeral_private = X25519PrivateKey.generate()
    server_nonce = os.urandom(NONCE_BYTES)
    server_hello = _create_hello(
        "server",
        identity,
        _ephemeral_public(ephemeral_private),
        server_nonce,
        peer_hello_hash=hashlib.sha256(_canonical(client_hello)).hexdigest(),
    )
    _send_json(sock, server_hello)
    key = _derive_key(
        ephemeral_private,
        client_ephemeral,
        client_hello,
        server_hello,
        client_nonce,
        server_nonce,
    )
    return AuthenticatedSession(key, device_id)
