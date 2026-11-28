
import unittest

from classical.xor import xor_encrypt

from classical.xor_recovery import (
    normalize_repeating_key,
    recover_repeating_xor_key,
    analyze_repeating_key_xor
)


class XorKeyNormalizationTests(unittest.TestCase):

    def setUp(self):

        self.plaintext = (
            b"Cryptography is the study of secure communication. "
            b"Encryption protects sensitive information. "
            b"Computer security uses cryptographic algorithms. "
            b"Students should understand encryption and decryption. "
            b"Frequency analysis helps discover unknown encryption keys. "
        ) * 5

        self.secret_key = b"LEMON"

        self.ciphertext = xor_encrypt(
            self.plaintext,
            self.secret_key
        )

    # Test 1: Normalize repeated key
    def test_normalize_repeated_key(self):

        result = normalize_repeating_key(
            b"LEMONLEMON"
        )

        self.assertEqual(result, b"LEMON")

    # Test 2: Normalize another repeated pattern
    def test_normalize_abc(self):

        result = normalize_repeating_key(
            b"ABCABCABC"
        )

        self.assertEqual(result, b"ABC")

    # Test 3: Keep a key without repetition
    def test_normalize_unique_key(self):

        result = normalize_repeating_key(
            b"SECRET"
        )

        self.assertEqual(result, b"SECRET")

    # Test 4: Recover key when estimated length is 10
    def test_recover_normalized_key(self):

        result = recover_repeating_xor_key(
            self.ciphertext,
            key_length=10
        )

        self.assertEqual(
            result["key"],
            self.secret_key
        )

        self.assertEqual(
            result["key_length"],
            5
        )

        self.assertEqual(
            result["plaintext"],
            self.plaintext
        )

    # Test 5: Automatic repeating XOR analysis
    def test_automatic_xor_analysis(self):

        candidates = analyze_repeating_key_xor(
            self.ciphertext,
            max_key_length=12,
            top_key_lengths=5
        )

        self.assertTrue(len(candidates) > 0)

        best = candidates[0]

        self.assertEqual(
            best["key"],
            self.secret_key
        )

        self.assertEqual(
            best["key_length"],
            5
        )

        self.assertEqual(
            best["plaintext"],
            self.plaintext
        )


if __name__ == "__main__":

    unittest.main(verbosity=2)
