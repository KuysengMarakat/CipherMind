
"""
Unit tests for CipherMind's main analysis pipeline.
"""

import unittest

from core.pipeline import run_pipeline


class PipelineTests(unittest.TestCase):

    def test_pipeline_rejects_empty_input(self):
        """Empty input must raise ValueError."""

        with self.assertRaises(ValueError):
            run_pipeline("")

    def test_pipeline_rejects_whitespace(self):
        """Whitespace-only input must raise ValueError."""

        with self.assertRaises(ValueError):
            run_pipeline("   ")

    def test_pipeline_rejects_invalid_input_type(self):
        """Non-string input must raise TypeError."""

        with self.assertRaises(TypeError):
            run_pipeline(None)

    def test_pipeline_returns_candidate_results(self):
        """Pipeline must return candidate results."""

        results = run_pipeline("KHOOR ZRUOG")

        self.assertIsInstance(results, list)

        self.assertTrue(len(results) > 0)

    def test_best_candidate_is_caesar(self):
        """Caesar Shift 3 should rank first for this test input."""

        results = run_pipeline("KHOOR ZRUOG")

        self.assertGreater(len(results), 0)

        self.assertEqual(
            results[0].plugin_name,
            "Caesar (Shift 3)"
        )

    def test_candidate_contains_decoded_bytes(self):
        """Successful candidates must contain decoded bytes."""

        results = run_pipeline("KHOOR ZRUOG")

        successful_results = [
            result for result in results
            if not result.error
        ]

        self.assertTrue(successful_results)

        for result in successful_results:

            self.assertIsInstance(
                result.decoded_data,
                bytes
            )

    def test_candidate_quality_score(self):
        """Quality score must be within the normalized range."""

        results = run_pipeline("KHOOR ZRUOG")

        best = results[0]

        self.assertIn(
            "quality_score",
            best.scores
        )

        score = best.scores["quality_score"]

        self.assertGreaterEqual(score, 0.0)

        self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
