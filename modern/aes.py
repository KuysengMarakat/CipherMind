"""Authenticated AES-GCM encryption and decryption.

AES-GCM provides confidentiality and integrity. Keep the key secret and NEVER
reuse a nonce with the same key. CipherMind generates a fresh 96-bit nonce by
default. This module is for data the user is authorized to protect or inspect.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes_key(key_size=256):
    """Generate an AES key. key_size must be 128, 192, or 256 bits."""
    if key_size not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192, or 256 bits")
    return AESGCM.generate_key(bit_length=key_size)


def aes_gcm_encrypt(key, plaintext, associated_data=None, nonce=None):
    """Encrypt bytes and return a dict containing nonce, ciphertext and tag."""
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("Associated data must be bytes or None")
    if nonce is None:
        nonce = os.urandom(12)
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")

    encrypted = AESGCM(key).encrypt(nonce, plaintext, associated_data)
    return {
        "nonce": nonce,
        "ciphertext": encrypted[:-16],
        "tag": encrypted[-16:],
        "algorithm": "AES-GCM",
    }


def aes_gcm_decrypt(key, nonce, ciphertext, tag, associated_data=None):
    """Authenticate and decrypt AES-GCM data. Invalid tags raise an exception."""
    if not isinstance(key, bytes) or len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be exactly 12 bytes")
    if not isinstance(ciphertext, bytes) or not isinstance(tag, bytes):
        raise TypeError("Ciphertext and tag must be bytes")
    if len(tag) != 16:
        raise ValueError("AES-GCM tag must be exactly 16 bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise TypeError("Associated data must be bytes or None")
    return AESGCM(key).decrypt(nonce, ciphertext + tag, associated_data)
