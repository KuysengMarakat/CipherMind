
import unittest

from core.pipeline import run_pipeline


class EncodingPluginTests(unittest.TestCase):

    PLAINTEXT = b"Hello World"

    def verify_encoding(self, encoded_data, expected_plugin):

        # Run the actual CipherMind pipeline
        results = run_pipeline(encoded_data)

        # Check that candidates were generated
        self.assertTrue(
            results,
            "Pipeline did not generate candidates"
        )

        # Get the highest-ranked candidate
        best = results[0]

        # Verify that execution succeeded
        self.assertFalse(
            best.error,
            f"Plugin returned an error: {best.error}"
        )

        # Verify the correct plugin was selected
        self.assertEqual(
            best.plugin_name,
            expected_plugin
        )

        # Verify decoded plaintext
        self.assertEqual(
            best.decoded_data,
            self.PLAINTEXT
        )

        # Verify scoring was performed
        self.assertIsInstance(
            best.scores,
            dict
        )

        self.assertIn(
            "quality_score",
            best.scores
        )

    def test_base64(self):

        encoded = "SGVsbG8gV29ybGQ="

        self.verify_encoding(
            encoded,
            "Base64"
        )

    def test_base32(self):

        encoded = "JBSWY3DPEBLW64TMMQ======"

        self.verify_encoding(
            encoded,
            "Base32"
        )

    def test_binary(self):

        encoded = (
            "01001000 01100101 "
            "01101100 01101100 "
            "01101111 00100000 "
            "01010111 01101111 "
            "01110010 01101100 "
            "01100100"
        )

        self.verify_encoding(
            encoded,
            "Binary"
        )

    def test_hexadecimal(self):

        encoded = "48656c6c6f20576f726c64"

        self.verify_encoding(
            encoded,
            "Hexadecimal"
        )


if __name__ == "__main__":

    unittest.main(verbosity=2)
