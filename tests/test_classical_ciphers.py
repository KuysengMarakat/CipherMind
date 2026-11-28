
import unittest

from core.pipeline import run_pipeline

from classical.caesar import caesar_decrypt

from classical.affine import (
    affine_decrypt,
    modular_inverse
)

from plugins.caesar_plugin import create_caesar_plugins

from plugins.affine_plugin import create_affine_plugins


class ClassicalCipherTests(unittest.TestCase):

    # =====================================
    # 1. CAESAR CIPHER TESTS
    # =====================================

    def test_caesar_recovery_through_pipeline(self):

        ciphertext = "KHOOR ZRUOG"

        results = run_pipeline(ciphertext)

        self.assertTrue(results)

        best = results[0]

        self.assertEqual(
            best.plugin_name,
            "Caesar (Shift 3)"
        )

        self.assertEqual(
            best.decoded_data,
            b"HELLO WORLD"
        )

        self.assertFalse(best.error)

        self.assertIn(
            "quality_score",
            best.scores
        )

    def test_caesar_preserves_punctuation(self):

        result = caesar_decrypt(
            "Khoor, ZRUOG!",
            3
        )

        self.assertEqual(
            result,
            "Hello, WORLD!"
        )

    def test_caesar_generates_all_shifts(self):

        plugins = create_caesar_plugins()

        self.assertEqual(
            len(plugins),
            26
        )

        shifts = sorted(
            plugin.shift for plugin in plugins
        )

        self.assertEqual(
            shifts,
            list(range(26))
        )

    # =====================================
    # 2. AFFINE CIPHER TESTS
    # =====================================

    def test_affine_recovery_through_pipeline(self):

        # Original plaintext: HELLO WORLD
        # Encryption keys: a=5, b=8

        ciphertext = "RCLLA OAPLX"

        results = run_pipeline(ciphertext)

        self.assertTrue(results)

        best = results[0]

        self.assertEqual(
            best.plugin_name,
            "Affine (a=5, b=8)"
        )

        self.assertEqual(
            best.decoded_data,
            b"HELLO WORLD"
        )

        self.assertFalse(best.error)

        self.assertIn(
            "quality_score",
            best.scores
        )

    def test_affine_preserves_case_and_punctuation(self):

        result = affine_decrypt(
            "Rclla, Oaplx!",
            5,
            8
        )

        self.assertEqual(
            result,
            "Hello, World!"
        )

    def test_affine_rejects_invalid_a(self):

        with self.assertRaises(ValueError):

            affine_decrypt(
                "HELLO",
                2,
                8
            )

    def test_affine_rejects_invalid_b(self):

        with self.assertRaises(ValueError):

            affine_decrypt(
                "HELLO",
                5,
                26
            )

    def test_affine_generates_all_keys(self):

        plugins = create_affine_plugins()

        # 12 valid multiplication keys * 26 addition keys

        self.assertEqual(
            len(plugins),
            312
        )

    # =====================================
    # 3. MODULAR INVERSE TESTS
    # =====================================

    def test_modular_inverse(self):

        result = modular_inverse(
            5,
            26
        )

        self.assertEqual(
            result,
            21
        )

        self.assertEqual(
            (5 * result) % 26,
            1
        )

    def test_modular_inverse_rejects_invalid_value(self):

        with self.assertRaises(ValueError):

            modular_inverse(
                2,
                26
            )


if __name__ == "__main__":

    unittest.main(verbosity=2)
