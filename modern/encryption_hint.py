"""
Explain unsolved input that looks like modern encryption (for example AES).

CipherMind cannot decrypt correctly used AES without the key. When no
chain solves the input, this module says whether the data looks like
block-cipher output and whether it shows the ECB-mode weakness.
"""

import base64
import binascii

from modern.aes_checks import find_repeated_blocks

BLOCK_SIZE = 16


def raw_bytes_from_input(text):
    """Decode input as hex, then Base64. Return bytes, or None."""
    cleaned = "".join(text.split())

    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        pass

    try:
        return base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError):
        return None


def looks_random(data):
    """Encrypted data is mostly non-printable bytes; text is not."""
    printable = sum(32 <= byte <= 126 for byte in data)
    return printable / len(data) < 0.75


def modern_encryption_hint(text):
    """
    Return a list of hint lines, or None if the input does not look
    like modern encrypted data.
    """
    data = raw_bytes_from_input(text)

    if data is None or len(data) < BLOCK_SIZE or not looks_random(data):
        return None

    lines = ["The decoded bytes look random, like modern encrypted data."]

    if len(data) % BLOCK_SIZE == 0:
        lines.append(
            f"Length is {len(data)} bytes, a multiple of 16: consistent "
            "with a block cipher such as AES."
        )

    repeated = find_repeated_blocks(data, BLOCK_SIZE)
    if repeated:
        lines.append(
            f"{len(repeated)} repeated 16-byte block(s) found: this suggests "
            "ECB mode, which leaks patterns in the plaintext."
        )

    lines.append(
        "Correctly used AES cannot be decrypted without the key. Look for "
        "the key, the IV or a usage mistake in the challenge files."
    )
    return lines
