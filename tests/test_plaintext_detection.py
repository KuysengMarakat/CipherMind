import unittest

from scoring.plaintext_detection import (
    is_likely_english_plaintext
)


class PlaintextDetectionTests(unittest.TestCase):

    def test_hello_world(self):
        self.assertTrue(
            is_likely_english_plaintext(
                b"HELLO WORLD"
            )
        )

    def test_computer_security_sentence(self):
        self.assertTrue(
            is_likely_english_plaintext(
                b"THE COMPUTER SECURITY SYSTEM"
            )
        )

    def test_cryptography_sentence(self):
        self.assertTrue(
            is_likely_english_plaintext(
                b"CRYPTOGRAPHY PROTECTS INFORMATION"
            )
        )

    def test_caesar_ciphertext(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"KHOOR ZRUOG"
            )
        )

    def test_random_looking_text(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"XQZP JKWT QWERTY ZXCVBN"
            )
        )

    def test_single_word_is_ambiguous(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"HELLO"
            )
        )

    def test_short_phrase_is_ambiguous(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"THE CAT"
            )
        )

    def test_numbers_only(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"1234567890"
            )
        )

    def test_empty_input(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b""
            )
        )

    def test_invalid_utf8(self):
        self.assertFalse(
            is_likely_english_plaintext(
                b"\xff\xfe\xfd"
            )
        )

    def test_invalid_input_type(self):
        with self.assertRaises(TypeError):
            is_likely_english_plaintext(
                "HELLO WORLD"
            )

    def test_low_quadgram_score(self):

        scores = {
            "printable_ratio": 1.0,
            "word_score": 1.0,
            "quality_score": 0.90,
            "quadgram_score": -8.0
        }

        self.assertFalse(
            is_likely_english_plaintext(
                b"HELLO WORLD",
                scores
            )
        )


if __name__ == "__main__":
    unittest.main()
