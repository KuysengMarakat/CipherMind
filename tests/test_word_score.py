import unittest

from scoring.word_score import (
    calculate_word_score,
    COMMON_WORDS
)


class WordScoreTests(unittest.TestCase):

    def test_hello_world(self):

        score = calculate_word_score(
            b"HELLO WORLD"
        )

        self.assertEqual(score, 1.0)

    def test_computer_security_sentence(self):

        score = calculate_word_score(
            b"THE COMPUTER SECURITY SYSTEM"
        )

        self.assertEqual(score, 1.0)

    def test_cryptography_sentence(self):

        score = calculate_word_score(
            b"CRYPTOGRAPHY PROTECTS INFORMATION"
        )

        self.assertEqual(score, 1.0)

    def test_unknown_words(self):

        score = calculate_word_score(
            b"ZXQJV KXQWZ"
        )

        self.assertEqual(score, 0.0)

    def test_empty_input(self):

        score = calculate_word_score(b"")

        self.assertEqual(score, 0.0)

    def test_numbers_only(self):

        score = calculate_word_score(
            b"1234567890"
        )

        self.assertEqual(score, 0.0)

    def test_invalid_utf8(self):

        score = calculate_word_score(
            b"\xff\xfe\xfd"
        )

        self.assertEqual(score, 0.0)

    def test_invalid_input_type(self):

        with self.assertRaises(TypeError):

            calculate_word_score("HELLO WORLD")

    def test_score_is_normalized(self):

        score = calculate_word_score(
            b"HELLO ZXQJV WORLD"
        )

        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_leetspeak_pieces_are_not_english(self):
        # Single letters such as "y", "e" and "s" left over from
        # leetspeak must not count as English words.
        score = calculate_word_score(
            b"PGS{y4l3e5_0s_p0q3}"
        )
        self.assertLess(score, 0.5)

    def test_real_short_words_still_count(self):
        score = calculate_word_score(
            b"I am a student of cryptography"
        )
        self.assertEqual(score, 1.0)

    def test_dictionary_loaded(self):

        self.assertGreater(
            len(COMMON_WORDS),
            1000
        )


if __name__ == "__main__":
    unittest.main()
