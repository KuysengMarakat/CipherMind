"""Unsolved input that looks like AES output gets an honest explanation."""

import base64
import contextlib
import io
import os
import unittest

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from main import analyze_once, build_parser
from modern.encryption_hint import modern_encryption_hint


def aes_ecb(plaintext):
    encryptor = Cipher(algorithms.AES(os.urandom(16)), modes.ECB()).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


class EncryptionHintTests(unittest.TestCase):
    def test_ecb_repeated_blocks_are_reported(self):
        ciphertext = aes_ecb(b"YELLOW SUBMARINE" * 4 + b"CTF{ecb_leaks!!}")
        hint = " ".join(modern_encryption_hint(ciphertext.hex()))
        self.assertIn("multiple of 16", hint)
        self.assertIn("ECB mode", hint)
        self.assertIn("cannot be decrypted without the key", hint)

    def test_base64_random_bytes_are_reported(self):
        hint = modern_encryption_hint(base64.b64encode(os.urandom(40)).decode())
        self.assertIsNotNone(hint)

    def test_readable_input_gets_no_hint(self):
        self.assertIsNone(modern_encryption_hint("the meeting is at dawn"))
        readable_hex = b"the secret meeting is at dawn".hex()
        self.assertIsNone(modern_encryption_hint(readable_hex))

    def test_hint_shown_from_paste_input(self):
        ciphertext = aes_ecb(b"YELLOW SUBMARINE" * 4 + b"CTF{ecb_leaks!!}")
        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        with contextlib.redirect_stdout(output):
            analyze_once(ciphertext.hex(), args)
        rendered = output.getvalue()
        self.assertIn("MODERN ENCRYPTION CHECK", rendered)
        self.assertIn("ECB mode", rendered)


if __name__ == "__main__":
    unittest.main()
