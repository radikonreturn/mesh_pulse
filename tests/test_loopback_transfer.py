"""Comprehensive loopback file-transfer integration tests.

Tests the full send/receive pipeline over localhost:
    - FileServer + FileClient with shared Fernet key
    - Varying file sizes (0 B, 1 KB, 500 KB)
    - Multi-file send
    - Transfer progress tracking
    - SHA-256 content verification
    - Error case: unreachable peer
    - on_file_received callback verification
"""

import hashlib
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from cryptography.fernet import Fernet

from mesh_pulse.core.transfer import (
    FileClient,
    FileServer,
    TransferDirection,
    TransferInfo,
    TransferStatus,
)


# Use unique high ports for each test to avoid conflicts
BASE_PORT = 19200


def _make_file(directory: str, name: str, size: int) -> str:
    """Create a test file with random content and return its path."""
    path = os.path.join(directory, name)
    with open(path, "wb") as f:
        f.write(os.urandom(size))
    return path


def _sha256(filepath: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _wait_for_transfers(
    server: FileServer,
    expected_count: int,
    timeout: float = 15.0,
) -> list[TransferInfo]:
    """Poll server transfers until expected_count are complete/failed."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        transfers = server.get_transfers()
        done = [
            t for t in transfers
            if t.status in (TransferStatus.COMPLETE, TransferStatus.FAILED)
        ]
        if len(done) >= expected_count:
            return transfers
        time.sleep(0.2)
    return server.get_transfers()


@pytest.fixture
def shared_key():
    """Generate a fresh Fernet key shared by server and client."""
    return Fernet.generate_key()


class TestLoopbackSingleFile:
    """Send a single file to localhost and verify it arrives intact."""

    def test_small_file_1kb(self, shared_key, tmp_path):
        """1 KB file: send → receive → verify content."""
        port = BASE_PORT + 1
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        src_path = _make_file(src_dir, "small.bin", 1024)
        src_hash = _sha256(src_path)

        server = FileServer(port=port, receive_dir=recv_dir, fernet_key=shared_key)
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send("127.0.0.1", src_path)
            transfers = _wait_for_transfers(server, 1)

            # Check transfer record
            assert len(transfers) >= 1
            info = transfers[-1]
            assert info.status == TransferStatus.COMPLETE
            assert info.direction == TransferDirection.RECV
            assert info.progress == 100.0
            assert info.filename == "small.bin"

            # Verify file content
            recv_path = os.path.join(recv_dir, "small.bin")
            assert os.path.exists(recv_path)
            assert _sha256(recv_path) == src_hash

        finally:
            server.shutdown()

    def test_medium_file_500kb(self, shared_key, tmp_path):
        """500 KB file: verify multi-chunk transfer and speed tracking."""
        port = BASE_PORT + 2
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        src_path = _make_file(src_dir, "medium.dat", 500 * 1024)
        src_hash = _sha256(src_path)

        server = FileServer(port=port, receive_dir=recv_dir, fernet_key=shared_key)
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send("127.0.0.1", src_path)
            transfers = _wait_for_transfers(server, 1)

            info = transfers[-1]
            assert info.status == TransferStatus.COMPLETE
            assert info.bytes_transferred == 500 * 1024
            assert info.speed_mbps >= 0

            recv_path = os.path.join(recv_dir, "medium.dat")
            assert _sha256(recv_path) == src_hash

        finally:
            server.shutdown()

    def test_empty_file_0b(self, shared_key, tmp_path):
        """0-byte file: edge case — should complete without errors."""
        port = BASE_PORT + 3
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        src_path = _make_file(src_dir, "empty.txt", 0)

        server = FileServer(port=port, receive_dir=recv_dir, fernet_key=shared_key)
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send("127.0.0.1", src_path)
            transfers = _wait_for_transfers(server, 1)

            info = transfers[-1]
            assert info.status == TransferStatus.COMPLETE
            assert info.progress == 100.0

            recv_path = os.path.join(recv_dir, "empty.txt")
            assert os.path.exists(recv_path)
            assert os.path.getsize(recv_path) == 0

        finally:
            server.shutdown()


class TestLoopbackMultiFile:
    """Send multiple files in one call."""

    def test_send_multiple_files(self, shared_key, tmp_path):
        """Send 3 files via send_multiple and verify all arrive."""
        port = BASE_PORT + 4
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        files = []
        hashes = {}
        for i in range(3):
            name = f"multi_{i}.bin"
            path = _make_file(src_dir, name, 2048 * (i + 1))
            files.append(path)
            hashes[name] = _sha256(path)

        server = FileServer(port=port, receive_dir=recv_dir, fernet_key=shared_key)
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send_multiple("127.0.0.1", files)
            transfers = _wait_for_transfers(server, 3, timeout=20)

            completed = [
                t for t in transfers if t.status == TransferStatus.COMPLETE
            ]
            assert len(completed) >= 3

            # Verify each file
            for name, expected_hash in hashes.items():
                recv_path = os.path.join(recv_dir, name)
                assert os.path.exists(recv_path), f"Missing: {name}"
                assert _sha256(recv_path) == expected_hash, f"Hash mismatch: {name}"

        finally:
            server.shutdown()


class TestTransferCallbacks:
    """Verify that on_file_received callback fires."""

    def test_callback_fires_on_complete(self, shared_key, tmp_path):
        """on_file_received must be called with a COMPLETE TransferInfo."""
        port = BASE_PORT + 5
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        src_path = _make_file(src_dir, "callback_test.bin", 4096)
        callback = MagicMock()

        server = FileServer(
            port=port,
            receive_dir=recv_dir,
            fernet_key=shared_key,
            on_file_received=callback,
        )
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send("127.0.0.1", src_path)
            _wait_for_transfers(server, 1)

            # Give a little extra time for callback to fire
            time.sleep(0.5)

            callback.assert_called_once()
            info: TransferInfo = callback.call_args[0][0]
            assert info.status == TransferStatus.COMPLETE
            assert info.filename == "callback_test.bin"
            assert info.peer_ip == "127.0.0.1"

        finally:
            server.shutdown()


class TestTransferClientTracking:
    """Verify that the FileClient tracks its own send transfers."""

    def test_client_records_send(self, shared_key, tmp_path):
        """FileClient.get_transfers() must show the sent file."""
        port = BASE_PORT + 6
        recv_dir = str(tmp_path / "received")
        os.makedirs(recv_dir)
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)

        src_path = _make_file(src_dir, "tracked.bin", 8192)

        server = FileServer(port=port, receive_dir=recv_dir, fernet_key=shared_key)
        client = FileClient(port=port, fernet_key=shared_key)

        server.start()
        time.sleep(0.3)

        try:
            client.send("127.0.0.1", src_path)
            _wait_for_transfers(server, 1)
            time.sleep(0.5)

            client_transfers = client.get_transfers()
            assert len(client_transfers) >= 1
            send_info = client_transfers[-1]
            assert send_info.direction == TransferDirection.SEND
            assert send_info.status == TransferStatus.COMPLETE
            assert send_info.filename == "tracked.bin"

        finally:
            server.shutdown()


class TestTransferErrorCase:
    """Verify graceful failure when the target is unreachable."""

    def test_send_to_unreachable_peer(self, shared_key, tmp_path):
        """Sending to a closed port must result in FAILED status."""
        src_dir = str(tmp_path / "source")
        os.makedirs(src_dir)
        src_path = _make_file(src_dir, "unreachable.bin", 512)

        client = FileClient(port=BASE_PORT + 99, fernet_key=shared_key)
        client.send("127.0.0.1", src_path)

        # Wait for the send thread to fail
        deadline = time.time() + 10
        while time.time() < deadline:
            transfers = client.get_transfers()
            if transfers and transfers[-1].status == TransferStatus.FAILED:
                break
            time.sleep(0.2)

        transfers = client.get_transfers()
        assert len(transfers) >= 1
        assert transfers[-1].status == TransferStatus.FAILED
        assert transfers[-1].error is not None
