"""Tests for AES-256-GCM encryption/decryption utilities."""

import os
import pytest

from mesh_pulse.utils.crypto import derive_key, encrypt_chunk, decrypt_chunk


class TestKeyDerivation:
    """Test PBKDF2 key derivation."""

    def test_derive_key_produces_32_bytes(self):
        key, salt = derive_key("test-passphrase")
        assert len(key) == 32
        assert len(salt) == 16

    def test_derive_key_deterministic_with_same_salt(self):
        key1, salt = derive_key("test-passphrase")
        key2, _ = derive_key("test-passphrase", salt=salt)
        assert key1 == key2

    def test_derive_key_different_with_different_salt(self):
        key1, salt1 = derive_key("test-passphrase")
        key2, salt2 = derive_key("test-passphrase")
        # Different random salts → different keys (with overwhelming probability)
        if salt1 != salt2:
            assert key1 != key2

    def test_derive_key_different_passphrases(self):
        key1, salt = derive_key("passphrase-one")
        key2, _ = derive_key("passphrase-two", salt=salt)
        assert key1 != key2


class TestEncryptDecrypt:
    """Test AES-256-GCM encrypt/decrypt round-trip."""

    def test_roundtrip_small_data(self):
        key, _ = derive_key("test-key")
        plaintext = b"Hello, Mesh-Pulse!"
        encrypted = encrypt_chunk(plaintext, key)
        decrypted = decrypt_chunk(encrypted, key)
        assert decrypted == plaintext

    def test_roundtrip_large_data(self):
        key, _ = derive_key("test-key")
        plaintext = os.urandom(64 * 1024)  # 64KB
        encrypted = encrypt_chunk(plaintext, key)
        decrypted = decrypt_chunk(encrypted, key)
        assert decrypted == plaintext

    def test_roundtrip_empty_data(self):
        key, _ = derive_key("test-key")
        plaintext = b""
        encrypted = encrypt_chunk(plaintext, key)
        decrypted = decrypt_chunk(encrypted, key)
        assert decrypted == plaintext

    def test_different_nonces_per_encryption(self):
        key, _ = derive_key("test-key")
        data = b"same data"
        enc1 = encrypt_chunk(data, key)
        enc2 = encrypt_chunk(data, key)
        # Nonces are random → ciphertexts differ
        assert enc1 != enc2
        # But both decrypt to the same plaintext
        assert decrypt_chunk(enc1, key) == data
        assert decrypt_chunk(enc2, key) == data

    def test_wrong_key_fails(self):
        key1, _ = derive_key("correct-key")
        key2, _ = derive_key("wrong-key")
        encrypted = encrypt_chunk(b"secret", key1)
        with pytest.raises(Exception):
            decrypt_chunk(encrypted, key2)

    def test_tampered_ciphertext_fails(self):
        key, _ = derive_key("test-key")
        encrypted = encrypt_chunk(b"important data", key)
        # Flip a byte in the ciphertext
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt_chunk(bytes(tampered), key)

    def test_encrypted_size_larger_than_plaintext(self):
        key, _ = derive_key("test-key")
        plaintext = b"x" * 1000
        encrypted = encrypt_chunk(plaintext, key)
        # nonce (12) + ciphertext + tag (16) > plaintext
        assert len(encrypted) > len(plaintext)
