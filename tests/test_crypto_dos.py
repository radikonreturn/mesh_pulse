import struct
import pytest
from unittest.mock import MagicMock
from mesh_pulse.utils.crypto import unpack_frame

def test_unpack_frame_dos_protection():
    # Mock socket that returns a huge length
    mock_sock = MagicMock()
    
    # Return 4 bytes for length (2GB), then nothing (simulation stops)
    huge_length = 2 * 1024 * 1024 * 1024 # 2GB
    mock_sock.recv.side_effect = [struct.pack(">I", huge_length)]
    
    with pytest.raises(ValueError, match="exceeds maximum allowed"):
        unpack_frame(mock_sock)

def test_unpack_frame_valid_size():
    mock_sock = MagicMock()
    payload = b"test"
    length = len(payload)
    
    # Return length then payload
    mock_sock.recv.side_effect = [struct.pack(">I", length), payload]
    
    result = unpack_frame(mock_sock)
    assert result == payload
