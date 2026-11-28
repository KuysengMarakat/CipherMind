import contextlib
import io
import unittest

from main import main


class ModernCliTests(unittest.TestCase):
    def test_hash_digest_command_is_routed_from_main(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main([
                "hash", "digest", "--algorithm", "sha256", "--text", "abc"
            ])
        self.assertEqual(result, 0)
        self.assertIn(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            output.getvalue(),
        )

    def test_hash_identify_command_is_routed_from_main(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = main(["hash", "identify", "--value", "a" * 64])
        self.assertEqual(result, 0)
        self.assertIn("SHA-256", output.getvalue())


class AutomaticHashDetectionTests(unittest.TestCase):
    def test_raw_md5_like_input_is_detected_in_normal_analysis(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        with contextlib.redirect_stdout(output):
            analyze_once("5d41402abc4b2a76b9719d911017c592", args)

        rendered = output.getvalue()
        self.assertIn("HASH INTELLIGENCE", rendered)
        self.assertIn("MD5, NTLM", rendered)
        self.assertIn("Routed to Hash Intelligence", rendered)
        self.assertIn("MATCH FOUND", rendered)
        self.assertIn("Algorithm matched : MD5", rendered)
        self.assertIn("Recovered value   : hello", rendered)
        self.assertNotIn("ANALYSIS RESULTS", rendered)


    def test_sha256_symbol_suffix_is_recovered_in_normal_prompt(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        digest = "40fce2e5fc047bdc4cee59773def025d0ca1425705f2b7b1e29985e8832e7d05"
        with contextlib.redirect_stdout(output):
            analyze_once(digest, args)

        rendered = output.getvalue()
        self.assertIn("Possible algorithm: SHA-256", rendered)
        self.assertIn("MATCH FOUND", rendered)
        self.assertIn("Recovered value   : hello@", rendered)

    def test_raw_hex_can_be_manually_routed_to_cryptanalysis(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once", "--force-cryptanalysis"])
        with contextlib.redirect_stdout(output):
            analyze_once("5d41402abc4b2a76b9719d911017c592", args)

        rendered = output.getvalue()
        self.assertIn("Manual override", rendered)
        # Cryptanalysis continues (search is the default) and no
        # dictionary audit is run.
        self.assertIn("MULTI-LAYER SEARCH", rendered)
        self.assertNotIn("AUTOMATIC DICTIONARY AUDIT", rendered)

    def test_hex_encoded_text_is_not_treated_as_hash(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        # 32 hex characters (MD5 length) that decode to "flag{hex_is_fun}".
        with contextlib.redirect_stdout(output):
            analyze_once("666c61677b6865785f69735f66756e7d", args)

        rendered = output.getvalue()
        self.assertIn("treating it as encoded data", rendered)
        self.assertNotIn("AUTOMATIC DICTIONARY AUDIT", rendered)
        self.assertIn("flag{hex_is_fun}", rendered)

    def test_bcrypt_like_input_is_routed_automatically(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        bcrypt_like = "$2b$12$" + ("a" * 53)
        with contextlib.redirect_stdout(output):
            analyze_once(bcrypt_like, args)

        rendered = output.getvalue()
        self.assertIn("Possible algorithm: bcrypt", rendered)
        self.assertIn("Password hashes are one-way", rendered)
        self.assertIn("AUTOMATIC DICTIONARY AUDIT", rendered)
        self.assertNotIn("ANALYSIS RESULTS", rendered)

    def test_argon2_like_input_is_routed_automatically(self):
        from main import analyze_once, build_parser

        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        argon2_like = "$argon2id$v=19$m=65536,t=3,p=4$example$saltandhash"
        with contextlib.redirect_stdout(output):
            analyze_once(argon2_like, args)

        rendered = output.getvalue()
        self.assertIn("Possible algorithm: Argon2id", rendered)
        self.assertIn("Routed to Hash Intelligence", rendered)
        self.assertIn("AUTOMATIC DICTIONARY AUDIT", rendered)
        self.assertNotIn("ANALYSIS RESULTS", rendered)

    def test_argon2_hash_can_be_audited_automatically(self):
        import importlib.util
        if importlib.util.find_spec("argon2") is None:
            self.skipTest("argon2-cffi is not installed")

        from main import analyze_once, build_parser
        from modern.hashing import hash_password_argon2

        encoded = hash_password_argon2(
            "hello", time_cost=1, memory_cost=8192, parallelism=1
        )
        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        with contextlib.redirect_stdout(output):
            analyze_once(encoded, args)

        rendered = output.getvalue()
        self.assertIn("MATCH FOUND", rendered)
        self.assertIn("Recovered value   : hello", rendered)


if __name__ == "__main__":
    unittest.main()
