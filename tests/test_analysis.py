
"""
Unit tests for CipherMind's classical cipher analysis.

These tests use the current core pipeline architecture.
"""

import unittest

from core.pipeline import run_pipeline


class CaesarTests(unittest.TestCase):

    def test_caesar_shift_three_recovery(self):
        """Verify that the pipeline recovers a Caesar shift of 3."""

        ciphertext = "KHOOR ZRUOG"

        expected_plaintext = b"HELLO WORLD"

        results = run_pipeline(ciphertext)

        # Find the Caesar Shift 3 result
        caesar_results = [
            result for result in results
            if result.plugin_name == "Caesar (Shift 3)"
            and not result.error
        ]

        self.assertTrue(
            caesar_results,
            "Caesar Shift 3 candidate was not found."
        )

        self.assertEqual(
            caesar_results[0].decoded_data,
            expected_plaintext
        )

    def test_caesar_candidate_has_scores(self):
        """Verify that Caesar results are evaluated by the scorer."""

        results = run_pipeline("KHOOR ZRUOG")

        caesar = next(
            (
                result for result in results
                if result.plugin_name == "Caesar (Shift 3)"
                and not result.error
            ),
            None
        )

        self.assertIsNotNone(caesar)

        self.assertIsInstance(caesar.scores, dict)

        self.assertIn(
            "quality_score",
            caesar.scores
        )

    def test_pipeline_returns_results(self):
        """Verify that the pipeline generates candidates."""

        results = run_pipeline("KHOOR ZRUOG")

        self.assertTrue(len(results) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
