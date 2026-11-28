"""The user pastes input with no options and CipherMind solves it."""

import contextlib
import io
import unittest

from main import analyze_once, build_parser


def run_without_options(data):
    """Run one analysis with default settings and return the output."""
    output = io.StringIO()
    args = build_parser().parse_args(["--once"])
    with contextlib.redirect_stdout(output):
        analyze_once(data, args)
    return output.getvalue()


class OneInputTests(unittest.TestCase):
    def test_proposal_example_needs_no_options(self):
        # hex -> Base64 -> ROT13, 56 hex characters (SHA-224 length).
        rendered = run_without_options(
            "5545645465336b3062444e6c4e563877"
            "633139774d48457a66513d3d"
        )
        self.assertIn(
            "#1  Hexadecimal -> Base64 -> Caesar (Shift 13)", rendered
        )
        self.assertIn("CTF{l4y3r5_0f_c0d3}", rendered)
        self.assertIn("FLAG PATTERN MATCHED", rendered)
        self.assertNotIn("AUTOMATIC DICTIONARY AUDIT", rendered)

    def test_substitution_cipher_is_solved(self):
        from classical.substitution import substitution_encrypt

        plaintext = (
            "cryptography is the practice and study of techniques for "
            "secure communication in the presence of adversarial behavior. "
            "more generally cryptography is about constructing and analyzing "
            "protocols that prevent third parties or the public from reading "
            "private messages"
        )
        ciphertext = substitution_encrypt(
            plaintext, "QWERTYUIOPASDFGHJKLZXCVBNM"
        )
        rendered = run_without_options(ciphertext)
        self.assertIn("#1  Automatic Substitution Analysis", rendered)
        self.assertIn("cryptography is the practice", rendered)

    def test_plain_english_falls_back_to_single_pass(self):
        rendered = run_without_options(
            "the meeting is at dawn near the old bridge"
        )
        self.assertIn("Original Plaintext", rendered)


class ChallengeFileTests(unittest.TestCase):
    def test_challenge_file_is_analysed(self):
        import os
        import tempfile

        from main import main

        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as handle:
            handle.write("5545645465336b3062444e6c4e563877633139774d48457a66513d3d\n")
            path = handle.name
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = main([path])
        finally:
            os.remove(path)

        self.assertEqual(exit_code, 0)
        self.assertIn("CTF{l4y3r5_0f_c0d3}", output.getvalue())

    def test_missing_file_gives_error_code(self):
        from main import main

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(["/no/such/challenge.txt"])
        self.assertEqual(exit_code, 1)
        self.assertIn("Cannot read challenge file", output.getvalue())


if __name__ == "__main__":
    unittest.main()
