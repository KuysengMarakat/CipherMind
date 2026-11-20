"""Unit tests for CipherMind's classical-cipher analysis."""

import unittest

from core.pipeline import analyze_caesar
from intelligence.frequency import index_of_coincidence
from plugins.caesar import decrypt_caesar
from validation.input import validate_top_n


class CaesarTests(unittest.TestCase):
    def test_decrypts_and_preserves_punctuation(self):
        self.assertEqual(decrypt_caesar("Khoor, ZRUOG!", 3), "Hello, WORLD!")

    def test_analyzer_ranks_expected_shift(self):
        result = analyze_caesar("Wklv lv d whvw phvvdjh. Wklv lv d whvw phvvdjh.")
        self.assertEqual(result.candidates[0].plaintext, "This is a test message. This is a test message.")

    def test_empty_letter_statistics_are_zero(self):
        self.assertEqual(index_of_coincidence(""), 0.0)

    def test_top_count_is_bounded(self):
        with self.assertRaises(ValueError):
            validate_top_n(27)


if __name__ == "__main__":
    unittest.main()
