"""Authenticated protocol-v3 handshake and trusted transfer tests."""

from __future__ import annotations

import base64
import os
import socket
import threading
import time
from types import SimpleNamespace

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from mesh_pulse.core.identity import DeviceIdentity
from mesh_pulse.core.session import (
    AuthenticationError,
    ProtocolError,
    _create_hello,
    _ephemeral_public,
    _send_json,
    client_handshake,
    server_handshake,
)
from mesh_pulse.core.transfer import (
    FileClient,
    FileServer,
    TransferStatus,
    _validate_file_header,
    _validate_session_header,
)
from mesh_pulse.core.trust import TrustStatus, TrustStore
from mesh_pulse.utils.crypto import decrypt_chunk, encrypt_chunk


def _identities_and_stores(tmp_path):
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    client_store = TrustStore(tmp_path / "client-trust.json")
    server_store = TrustStore(tmp_path / "server-trust.json")
    server_record = client_store.trust(
        server_identity.device_id, "server", server_identity.public_key
    )
    server_store.trust(client_identity.device_id, "client", client_identity.public_key)
    return (
        client_identity,
        server_identity,
        client_store,
        server_store,
        server_record,
    )


def _handshake_once(tmp_path):
    client_identity, server_identity, _, server_store, server_record = (
        _identities_and_stores(tmp_path)
    )
    client_socket, server_socket = socket.socketpair()
    outcome = {}

    def run_server() -> None:
        try:
            outcome["server"] = server_handshake(
                server_socket, server_identity, server_store
            )
        except (AuthenticationError, ProtocolError, OSError) as error:
            outcome["error"] = error
        finally:
            server_socket.close()

    thread = threading.Thread(target=run_server)
    thread.start()
    try:
        client_result = client_handshake(client_socket, client_identity, server_record)
    finally:
        client_socket.close()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert "error" not in outcome
    return client_result, outcome["server"]


def test_successful_trusted_handshake(tmp_path):
    client_result, server_result = _handshake_once(tmp_path)
    assert client_result.key == server_result.key
    assert len(client_result.key) == 32
    assert client_result.peer_device_id != server_result.peer_device_id


def test_session_keys_differ_between_connections(tmp_path):
    first_client, _ = _handshake_once(tmp_path / "one")
    second_client, _ = _handshake_once(tmp_path / "two")
    assert first_client.key != second_client.key


def test_untrusted_handshake_rejected(tmp_path):
    client_identity = DeviceIdentity.load_or_create(tmp_path / "client")
    server_identity = DeviceIdentity.load_or_create(tmp_path / "server")
    server_store = TrustStore(tmp_path / "empty-trust.json")
    sender, receiver = socket.socketpair()
    hello = _create_hello(
        "client",
        client_identity,
        _ephemeral_public(X25519PrivateKey.generate()),
        os.urandom(32),
    )
    _send_json(sender, hello)
    with pytest.raises(AuthenticationError, match="Untrusted"):
        server_handshake(receiver, server_identity, server_store)
    sender.close()
    receiver.close()


def test_signature_verification_failure(tmp_path):
    client_identity, server_identity, _, server_store, _ = _identities_and_stores(
        tmp_path
    )
    sender, receiver = socket.socketpair()
    hello = _create_hello(
        "client",
        client_identity,
        _ephemeral_public(X25519PrivateKey.generate()),
        os.urandom(32),
    )
    signature = bytearray(base64.b64decode(hello["signature"]))
    signature[-1] ^= 1
    hello["signature"] = base64.b64encode(signature).decode()
    _send_json(sender, hello)
    with pytest.raises(AuthenticationError, match="Signature"):
        server_handshake(receiver, server_identity, server_store)
    sender.close()
    receiver.close()


def test_protocol_version_mismatch(tmp_path):
    client_identity, server_identity, _, server_store, _ = _identities_and_stores(
        tmp_path
    )
    sender, receiver = socket.socketpair()
    hello = _create_hello(
        "client",
        client_identity,
        _ephemeral_public(X25519PrivateKey.generate()),
        os.urandom(32),
    )
    hello["protocol"] = 2
    _send_json(sender, hello)
    with pytest.raises(ProtocolError, match="version"):
        server_handshake(receiver, server_identity, server_store)
    sender.close()
    receiver.close()


@pytest.mark.parametrize(
    "header",
    [
        {"type": "file", "name": "", "size": 1, "sha256": "a" * 64},
        {"type": "file", "name": "ok", "size": -1, "sha256": "a" * 64},
        {"type": "file", "name": "ok", "size": 1, "sha256": "invalid"},
    ],
)
def test_invalid_file_metadata_rejected(header):
    with pytest.raises(ProtocolError):
        _validate_file_header(header)


def test_invalid_session_file_count_rejected():
    with pytest.raises(ProtocolError, match="file count"):
        _validate_session_header(
            {"type": "session", "version": 3, "count": 1_000_000}, 3
        )


def test_wrong_peer_identity_rejected(tmp_path):
    client_identity, server_identity, _, server_store, _ = _identities_and_stores(
        tmp_path
    )
    wrong_identity = DeviceIdentity.load_or_create(tmp_path / "wrong")
    client_store = TrustStore(tmp_path / "wrong-client-trust.json")
    wrong_record = client_store.trust(
        wrong_identity.device_id, "wrong", wrong_identity.public_key
    )
    client_socket, server_socket = socket.socketpair()

    def run_server() -> None:
        try:
            server_handshake(server_socket, server_identity, server_store)
        except (AuthenticationError, ProtocolError, OSError):
            return
        finally:
            server_socket.close()

    thread = threading.Thread(target=run_server)
    thread.start()
    with pytest.raises(AuthenticationError, match="Wrong peer"):
        client_handshake(client_socket, client_identity, wrong_record)
    client_socket.close()
    thread.join(timeout=2)


def test_tampered_session_payload_rejected(tmp_path):
    client_result, _ = _handshake_once(tmp_path)
    encrypted = bytearray(encrypt_chunk(b"trusted payload", client_result.key))
    encrypted[-1] ^= 1
    with pytest.raises(InvalidTag):
        decrypt_chunk(bytes(encrypted), client_result.key)


def test_trusted_v3_loopback_transfer(tmp_path):
    port = 19450
    client_identity, server_identity, client_store, server_store, _ = (
        _identities_and_stores(tmp_path)
    )
    source = tmp_path / "source.bin"
    source.write_bytes(os.urandom(8192))
    receive_dir = tmp_path / "received"
    server = FileServer(
        port=port,
        receive_dir=str(receive_dir),
        identity=server_identity,
        trust_store=server_store,
        legacy_mode=False,
    )
    peer = SimpleNamespace(
        device_id=server_identity.device_id,
        public_key=server_identity.public_key,
        trust_status=TrustStatus.TRUSTED,
    )
    client = FileClient(
        port=port,
        identity=client_identity,
        trust_store=client_store,
        peer_resolver=lambda _ip: peer,
        legacy_mode=False,
    )
    server.start()
    time.sleep(0.2)
    try:
        client.send("127.0.0.1", str(source))
        deadline = time.time() + 5
        while time.time() < deadline:
            records = server.get_transfers()
            if records and records[-1].status in {
                TransferStatus.COMPLETE,
                TransferStatus.FAILED,
            }:
                break
            time.sleep(0.05)
        assert server.get_transfers()[-1].status == TransferStatus.COMPLETE
        assert (receive_dir / source.name).read_bytes() == source.read_bytes()
        assert server.get_transfers()[-1].peer_device_id == client_identity.device_id
    finally:
        server.shutdown()
