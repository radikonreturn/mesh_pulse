"""Tests for path traversal prevention in file transfer.

Verifies that the FileServer sanitizes incoming filenames so that
a malicious sender cannot write files outside the receive directory.
Uses the v2 AES-256-GCM JSON-framed protocol.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import time

import pytest

from mesh_pulse.core.transfer import FileServer
from mesh_pulse.utils.crypto import derive_session_key, encrypt_chunk, pack_frame

TEST_PORT = 11000
TEST_PASSPHRASE = "traversal-test-key"
TEST_RECEIVE_DIR = "test_received_traversal"


def _send_frame(sock: socket.socket, key: bytes, payload: dict | bytes) -> None:
    """Helper: encrypt and send a length-prefixed frame (v2 protocol)."""
    if isinstance(payload, dict):
        raw = json.dumps(payload).encode("utf-8")
    else:
        raw = payload
    encrypted = encrypt_chunk(raw, key)
    sock.sendall(pack_frame(encrypted))


@pytest.fixture
def clean_dirs():
    """Create and tear down a clean receive directory."""
    if os.path.exists(TEST_RECEIVE_DIR):
        shutil.rmtree(TEST_RECEIVE_DIR)
    os.makedirs(TEST_RECEIVE_DIR, exist_ok=True)
    yield
    if os.path.exists(TEST_RECEIVE_DIR):
        shutil.rmtree(TEST_RECEIVE_DIR)
    # Cleanup escaped file if the sanitization somehow failed
    if os.path.exists("escaped_file.txt"):
        os.remove("escaped_file.txt")


def test_path_traversal(clean_dirs):
    """Malicious filename with '../' must be sanitized to just the basename."""
    key = derive_session_key(TEST_PASSPHRASE)

    server = FileServer(
        port=TEST_PORT,
        receive_dir=TEST_RECEIVE_DIR,
        passphrase=TEST_PASSPHRASE,
    )
    server.start()
    time.sleep(0.5)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT))

        content = b"hacked content"
        file_hash = hashlib.sha256(content).hexdigest()
        malicious_filename = "../escaped_file.txt"

        # ── v2 session header ──
        _send_frame(sock, key, {"type": "session", "version": 2, "count": 1})

        # ── v2 file header with malicious filename ──
        _send_frame(
            sock,
            key,
            {
                "type": "file",
                "name": malicious_filename,
                "size": len(content),
                "sha256": file_hash,
            },
        )

        # ── Data chunk ──
        _send_frame(sock, key, content)

        # ── FIN ──
        _send_frame(sock, key, {"type": "fin"})

        sock.close()
        time.sleep(1.0)

        # The file must NOT escape the receive directory
        escaped_path = os.path.abspath("escaped_file.txt")
        assert not os.path.exists(escaped_path), (
            "Path traversal succeeded — file was created outside receive dir!"
        )

        # The file SHOULD exist inside the receive directory (sanitized)
        safe_path = os.path.join(TEST_RECEIVE_DIR, "escaped_file.txt")
        assert os.path.exists(safe_path), (
            "Sanitized file was not created in the receive directory."
        )

        # Verify content integrity
        with open(safe_path, "rb") as f:
            assert f.read() == content

    finally:
        server.shutdown()
