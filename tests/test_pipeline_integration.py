import unittest

from core.pipeline import run_pipeline


class PipelineIntegrationTests(unittest.TestCase):

    def check_result(self, input_text, expected_plugin, expected_text):

        results = run_pipeline(input_text)

        self.assertTrue(results)

        best = results[0]

        self.assertEqual(
            best.plugin_name,
            expected_plugin
        )

        self.assertEqual(
            best.decoded_data.decode("utf-8"),
            expected_text
        )

        self.assertIsNone(best.error)

    def test_original_plaintext(self):
        self.check_result(
            "HELLO WORLD",
            "Original Plaintext",
            "HELLO WORLD"
        )

    def test_english_sentence(self):
        self.check_result(
            "THE COMPUTER SECURITY SYSTEM",
            "Original Plaintext",
            "THE COMPUTER SECURITY SYSTEM"
        )

    def test_caesar_recovery(self):
        self.check_result(
            "KHOOR ZRUOG",
            "Caesar (Shift 3)",
            "HELLO WORLD"
        )

    def test_base32_decoding(self):
        self.check_result(
            "JBSWY3DP",
            "Base32",
            "Hello"
        )


if __name__ == "__main__":
    unittest.main()
