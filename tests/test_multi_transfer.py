"""Tests for multiple file transfer logic."""

import os
import tempfile
from unittest.mock import MagicMock, patch
from mesh_pulse.core.transfer import SecureTransfer

def test_send_file_multi_call():
    """Verify that send_file correctly handles a list of files."""
    with patch("threading.Thread") as mock_thread:
        xfer = SecureTransfer(passphrase="test")
        files = ["file1.txt", "file2.txt", "file3.txt"]
        
        # We don't need real files for this mock test because the thread 
        # is what starts the worker which checks for the file.
        # But let's check how it's called.
        xfer.send_file("127.0.0.1", files)
        
        assert mock_thread.call_count == 3
        # Verify it passed the correct filenames to the workers
        args_list = [call.kwargs['args'] for call in mock_thread.call_args_list]
        passed_files = [args[1] for args in args_list]
        assert set(passed_files) == set(files)

def test_send_file_single_call():
    """Verify that send_file still handles a single string correctly."""
    with patch("threading.Thread") as mock_thread:
        xfer = SecureTransfer(passphrase="test")
        file = "file1.txt"
        
        xfer.send_file("127.0.0.1", file)
        
        assert mock_thread.call_count == 1
        assert mock_thread.call_args.kwargs['args'][1] == file
