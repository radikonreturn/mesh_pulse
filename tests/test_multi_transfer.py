"""Tests for multiple file transfer logic (v2 session-batching protocol)."""

from __future__ import annotations

from unittest.mock import patch

from mesh_pulse.core.transfer import SecureTransfer


def test_send_file_multi_call():
    """send_file() with a list of files dispatches a single batch thread."""
    with patch("threading.Thread") as mock_thread:
        xfer = SecureTransfer(passphrase="test")
        files = ["file1.txt", "file2.txt", "file3.txt"]

        # v2: all files are bundled into one batch thread (one TCP session)
        xfer.send_file("127.0.0.1", files)

        # One batch thread should have been created
        assert mock_thread.call_count == 1
        # The filepaths list should be passed as the second positional arg
        call_args = mock_thread.call_args
        passed_files = call_args.kwargs["args"][1]
        assert set(passed_files) == set(files)


def test_send_file_single_call():
    """send_file() with a single string wraps it in a list for the batch worker."""
    with patch("threading.Thread") as mock_thread:
        xfer = SecureTransfer(passphrase="test")
        file = "file1.txt"

        xfer.send_file("127.0.0.1", file)

        assert mock_thread.call_count == 1
        call_args = mock_thread.call_args
        passed_files = call_args.kwargs["args"][1]
        # Single file is converted to a one-element list
        assert passed_files == [file]
