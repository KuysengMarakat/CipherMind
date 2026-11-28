import base64
import unittest

from CandidateGenerator.candidate_generation import CandidateGenerator
from decoders.extra_decoders import (
    decode_base85, decode_octal, decode_decimal, decode_url,
    decode_html_entities, decode_morse, decode_base58_text,
)


class ExtraEncodingTests(unittest.TestCase):
    def test_base58(self):
        self.assertEqual(decode_base58_text("JxF12TrwUP45BMd"), b"Hello World")

    def test_base85(self):
        encoded = base64.b85encode(b"Hello World").decode("ascii")
        self.assertEqual(decode_base85(encoded), b"Hello World")

    def test_octal(self):
        self.assertEqual(decode_octal("110 145 154 154 157"), b"Hello")

    def test_decimal(self):
        self.assertEqual(decode_decimal("72 101 108 108 111"), b"Hello")

    def test_url(self):
        self.assertEqual(decode_url("Hello%20World%21"), b"Hello World!")

    def test_html_entities(self):
        self.assertEqual(decode_html_entities("Hello&#32;World&#33;"), b"Hello World!")

    def test_morse(self):
        self.assertEqual(
            decode_morse(".... . .-.. .-.. --- / .-- --- .-. .-.. -.."),
            b"HELLO WORLD",
        )

    def test_extra_encodings_are_selected(self):
        generator = CandidateGenerator()
        examples = {
            "base58": "JxF12TrwUP45BMd",
            "octal": "110 145 154 154 157",
            "decimal": "72 101 108 108 111",
            "url": "Hello%20World%21",
            "html": "Hello&#32;World&#33;",
            "morse": ".... . .-.. .-.. --- / .-- --- .-. .-.. -..",
        }
        for expected, value in examples.items():
            with self.subTest(expected=expected):
                self.assertEqual(generator.detect_input_mode(value), expected)

    def test_invalid_decimal_is_rejected(self):
        with self.assertRaises(ValueError):
            decode_decimal("256 300")


if __name__ == "__main__":
    unittest.main()
