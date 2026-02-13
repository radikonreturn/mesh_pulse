"""Tests for path traversal prevention in file transfer.

Verifies that the FileServer sanitizes incoming filenames so that
a malicious sender cannot write files outside the receive directory.
"""

import hashlib
import os
import shutil
import socket
import time

import pytest

from mesh_pulse.core.transfer import FileServer
from mesh_pulse.utils.crypto import fernet_encrypt, load_or_generate_key, pack_frame


TEST_PORT = 11000
TEST_RECEIVE_DIR = "test_received_traversal"


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
    key = load_or_generate_key()

    server = FileServer(
        port=TEST_PORT,
        receive_dir=TEST_RECEIVE_DIR,
        fernet_key=key,
    )
    server.start()
    time.sleep(0.5)  # Let the server bind

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(("127.0.0.1", TEST_PORT))

        # Craft a malicious header with path traversal
        content = b"hacked content"
        file_hash = hashlib.sha256(content).hexdigest()
        malicious_filename = "../escaped_file.txt"
        header_str = f"{malicious_filename}|{len(content)}|{file_hash}"

        # Send Fernet-encrypted header (matching FileServer protocol)
        enc_header = fernet_encrypt(header_str.encode("utf-8"), key)
        sock.sendall(pack_frame(enc_header))

        # Send Fernet-encrypted content chunk
        enc_content = fernet_encrypt(content, key)
        sock.sendall(pack_frame(enc_content))

        sock.close()
        time.sleep(1)  # Let server process

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

        # Verify content
        with open(safe_path, "rb") as f:
            assert f.read() == content

    finally:
        server.shutdown()
