"""Tests for secure file transfer protocol."""

import json
import math
import os
import tempfile
import threading
import time

import pytest

from mesh_pulse.core.transfer import (
    SecureTransfer,
    TransferDirection,
    TransferInfo,
    TransferStatus,
)
from mesh_pulse.utils.crypto import derive_key, encrypt_chunk, decrypt_chunk


class TestTransferInfo:
    """Test TransferInfo dataclass."""

    def test_progress_calculation(self):
        info = TransferInfo(
            filename="test.bin",
            filesize=1000,
            direction=TransferDirection.SEND,
            peer_ip="1.2.3.4",
        )
        info.bytes_transferred = 500
        assert info.progress == 50.0

    def test_progress_zero_filesize(self):
        info = TransferInfo(
            filename="empty.txt",
            filesize=0,
            direction=TransferDirection.SEND,
            peer_ip="1.2.3.4",
        )
        assert info.progress == 100.0

    def test_progress_complete(self):
        info = TransferInfo(
            filename="test.bin",
            filesize=1000,
            direction=TransferDirection.RECV,
            peer_ip="1.2.3.4",
        )
        info.bytes_transferred = 1000
        assert info.progress == 100.0

    def test_speed_calculation(self):
        info = TransferInfo(
            filename="test.bin",
            filesize=10 * 1024 * 1024,
            direction=TransferDirection.SEND,
            peer_ip="1.2.3.4",
        )
        info.bytes_transferred = 5 * 1024 * 1024
        # Speed depends on elapsed time; just verify it returns a float
        assert isinstance(info.speed_mbps, float)
        assert info.speed_mbps >= 0

    def test_to_dict(self):
        info = TransferInfo(
            filename="report.pdf",
            filesize=2048,
            direction=TransferDirection.SEND,
            peer_ip="192.168.1.10",
            status=TransferStatus.ACTIVE,
        )
        info.bytes_transferred = 1024
        d = info.to_dict()
        assert d["filename"] == "report.pdf"
        assert d["direction"] == "send"
        assert d["status"] == "active"
        assert d["progress"] == 50.0


class TestSecureTransferIntegration:
    """Integration test: send and receive a file via localhost."""

    def test_localhost_file_transfer(self):
        """Full round-trip: create file → send → receive → verify."""
        passphrase = "integration-test-key"
        port = 18765  # Use a high port to avoid conflicts

        # Create a temporary file to send
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            test_data = os.urandom(128 * 1024)  # 128KB
            f.write(test_data)
            src_path = f.name

        with tempfile.TemporaryDirectory() as recv_dir:
            try:
                # Start receiver
                receiver = SecureTransfer(
                    passphrase=passphrase,
                    transfer_port=port,
                    receive_dir=recv_dir,
                )
                receiver.start_server()
                time.sleep(0.3)  # let server bind

                # Start sender
                sender = SecureTransfer(
                    passphrase=passphrase,
                    transfer_port=port,
                )
                sender.send_file("127.0.0.1", src_path)

                # Wait for transfer to complete
                deadline = time.time() + 10  # 10s timeout
                while time.time() < deadline:
                    recv_transfers = receiver.get_transfers()
                    if recv_transfers and recv_transfers[-1].status in (
                        TransferStatus.COMPLETE,
                        TransferStatus.FAILED,
                    ):
                        break
                    time.sleep(0.2)

                # Verify
                recv_transfers = receiver.get_transfers()
                assert len(recv_transfers) >= 1
                last = recv_transfers[-1]
                assert last.status == TransferStatus.COMPLETE

                # Verify file content
                recv_path = os.path.join(recv_dir, os.path.basename(src_path))
                assert os.path.exists(recv_path)
                with open(recv_path, "rb") as rf:
                    received_data = rf.read()
                assert received_data == test_data

            finally:
                receiver.stop_server()
                os.unlink(src_path)
