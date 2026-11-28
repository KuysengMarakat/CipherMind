"""Educational DES and 3DES-CBC support for legacy data only.

DES and 3DES are obsolete and must not be selected for new systems. CBC is
unauthenticated; use AES-GCM for new designs. This module exists for learning,
interoperability, and authorized legacy-data handling.
"""
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.primitives.padding import PKCS7


def _validate_inputs(key, iv, data):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")
    if len(key) not in (8, 16, 24):
        raise ValueError("DES uses an 8-byte key; 3DES uses a 16- or 24-byte key")
    if not isinstance(iv, bytes) or len(iv) != 8:
        raise ValueError("DES/3DES CBC IV must be exactly 8 bytes")
    if not isinstance(data, bytes):
        raise TypeError("Input data must be bytes")


def des_cbc_encrypt(key, iv, plaintext):
    """Encrypt with single DES-CBC (8-byte key); legacy/educational only."""
    if not isinstance(key, bytes) or len(key) != 8:
        raise ValueError("Single DES key must be exactly 8 bytes")
    return _cbc_encrypt(key, iv, plaintext)


def des_cbc_decrypt(key, iv, ciphertext):
    """Decrypt single DES-CBC (8-byte key); legacy/educational only."""
    if not isinstance(key, bytes) or len(key) != 8:
        raise ValueError("Single DES key must be exactly 8 bytes")
    return _cbc_decrypt(key, iv, ciphertext)


def triple_des_cbc_encrypt(key, iv, plaintext):
    """Encrypt with 2-key (16-byte) or 3-key (24-byte) 3DES-CBC."""
    if not isinstance(key, bytes) or len(key) not in (16, 24):
        raise ValueError("3DES key must be exactly 16 or 24 bytes")
    return _cbc_encrypt(key, iv, plaintext)


def triple_des_cbc_decrypt(key, iv, ciphertext):
    """Decrypt with 2-key (16-byte) or 3-key (24-byte) 3DES-CBC."""
    if not isinstance(key, bytes) or len(key) not in (16, 24):
        raise ValueError("3DES key must be exactly 16 or 24 bytes")
    return _cbc_decrypt(key, iv, ciphertext)


def _cbc_encrypt(key, iv, plaintext):
    _validate_inputs(key, iv, plaintext)
    padder = PKCS7(64).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _cbc_decrypt(key, iv, ciphertext):
    _validate_inputs(key, iv, ciphertext)
    if not ciphertext or len(ciphertext) % 8:
        raise ValueError("DES/3DES CBC ciphertext length must be a non-zero multiple of 8")
    decryptor = Cipher(TripleDES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(64).unpadder()
    return unpadder.update(padded) + unpadder.finalize()
