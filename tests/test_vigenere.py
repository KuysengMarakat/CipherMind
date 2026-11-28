
import unittest

from classical.vigenere import (
    vigenere_encrypt,
    vigenere_decrypt,
    validate_key
)

from classical.vigenere_analysis import (
    calculate_ioc,
    estimate_key_lengths
)

from classical.kasiski import kasiski_examination

from classical.vigenere_recovery import (
    recover_vigenere_key
)

from classical.vigenere_attack import (
    analyze_vigenere
)

from plugins.vigenere_attack_plugin import (
    VigenereAttackPlugin
)


class VigenereTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):

        cls.key = "LEMON"

        paragraphs = [

            "Cryptography is the study of secure communication. "

            "Encryption protects sensitive information and data. "

            "Students should understand how encryption works.",

            "Computer security uses cryptographic algorithms to "

            "protect messages and communication between users.",

            "Frequency analysis helps security researchers discover "

            "weaknesses in classical encryption algorithms.",

            "Vigenere encryption uses a repeating secret key to "

            "transform readable plaintext into ciphertext."

        ]

        cls.plaintext = " ".join(paragraphs * 8)

        cls.ciphertext = vigenere_encrypt(
            cls.plaintext,
            cls.key
        )


    # Test 1: Standard encryption example

    def test_standard_encryption(self):

        encrypted = vigenere_encrypt(
            "ATTACKATDAWN",
            "LEMON"
        )

        self.assertEqual(
            encrypted,
            "LXFOPVEFRNHR"
        )


    # Test 2: Decryption

    def test_standard_decryption(self):

        decrypted = vigenere_decrypt(
            "LXFOPVEFRNHR",
            "LEMON"
        )

        self.assertEqual(
            decrypted,
            "ATTACKATDAWN"
        )


    # Test 3: Encryption and decryption round trip

    def test_encryption_decryption_round_trip(self):

        encrypted = vigenere_encrypt(
            self.plaintext,
            self.key
        )

        decrypted = vigenere_decrypt(
            encrypted,
            self.key
        )

        self.assertEqual(
            decrypted,
            self.plaintext
        )


    # Test 4: Preserve case and punctuation

    def test_preserve_case_and_punctuation(self):

        message = "Attack at Dawn! 123"

        encrypted = vigenere_encrypt(
            message,
            self.key
        )

        decrypted = vigenere_decrypt(
            encrypted,
            self.key
        )

        self.assertEqual(
            decrypted,
            message
        )


    # Test 5: Validate secret keys

    def test_invalid_keys(self):

        with self.assertRaises(ValueError):
            validate_key("")

        with self.assertRaises(ValueError):
            validate_key("LEMON123")

        with self.assertRaises(ValueError):
            validate_key("LEMON!")

        with self.assertRaises(TypeError):
            validate_key(123)


    # Test 6: Index of Coincidence

    def test_index_of_coincidence(self):

        self.assertEqual(
            calculate_ioc(""),
            0.0
        )

        self.assertEqual(
            calculate_ioc("A"),
            0.0
        )

        self.assertEqual(
            calculate_ioc("AAAA"),
            1.0
        )


    # Test 7: Estimate repeating key length

    def test_key_length_estimation(self):

        results = estimate_key_lengths(
            self.ciphertext,
            max_key_length=12
        )

        self.assertTrue(
            len(results) > 0
        )

        estimated_lengths = [
            item["key_length"]
            for item in results
        ]

        self.assertIn(
            len(self.key),
            estimated_lengths
        )


    # Test 8: Kasiski examination

    def test_kasiski_examination(self):

        block = "THEQUICKBROWNFOXJUMPSOVER"

        repeated_plaintext = block * 4

        encrypted = vigenere_encrypt(
            repeated_plaintext,
            self.key
        )

        results = kasiski_examination(
            encrypted,
            max_key_length=12
        )

        possible_lengths = [
            item["key_length"]
            for item in results
        ]

        self.assertIn(
            5,
            possible_lengths
        )


    # Test 9: Recover the secret key

    def test_recover_vigenere_key(self):

        result = recover_vigenere_key(
            self.ciphertext,
            len(self.key)
        )

        self.assertEqual(
            result["key"],
            self.key
        )

        self.assertEqual(
            result["plaintext"],
            self.plaintext
        )


    # Test 10: Automatic Vigenere analysis

    def test_automatic_vigenere_analysis(self):

        result = analyze_vigenere(
            self.ciphertext,
            max_key_length=12
        )

        self.assertTrue(
            len(result["candidates"]) > 0
        )

        recovered = [
            candidate["plaintext"]
            for candidate in result["candidates"]
        ]

        self.assertIn(
            self.plaintext,
            recovered
        )


    # Test 10b: Short ciphertext (about 100 letters).
    # Frequency analysis alone recovered "MEMNN" instead of "LEMON";
    # quadgram hill climbing must fix the key.

    def test_short_text_key_is_refined(self):

        plaintext = (
            "the quick brown fox jumps over the lazy dog while the "
            "secret message hides inside a longer english sentence"
        )

        for key in ["LEMON", "CRYPTO", "KEY", "SECURITY"]:

            ciphertext = vigenere_encrypt(plaintext, key)

            result = analyze_vigenere(ciphertext, max_key_length=12)

            best = result["candidates"][0]

            self.assertEqual(best["key"], key)
            self.assertEqual(best["plaintext"], plaintext)


    # Test 11: Automatic attack plugin

    def test_vigenere_attack_plugin(self):

        plugin = VigenereAttackPlugin()

        detection = plugin.detect(
            self.ciphertext
        )

        self.assertGreater(
            detection,
            0
        )

        recovered = plugin.apply(
            self.ciphertext
        )

        self.assertIsInstance(
            recovered,
            bytes
        )

        self.assertIsNotNone(
            plugin.best_candidate
        )


if __name__ == "__main__":

    unittest.main(verbosity=2)
