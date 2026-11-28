import importlib.util
import tempfile
import unittest

from modern.hashing import (
    calculate_digest,
    hash_password_argon2,
    verify_password_argon2,
    audit_password_hash,
    hash_password_bcrypt,
    verify_password_bcrypt,
)
from modern.hash_identifier import identify_hash
from modern.hash_cracking import crack_raw_digest, md4


class HashingTests(unittest.TestCase):
    def test_known_digest_values(self):
        self.assertEqual(
            calculate_digest("abc", "sha256"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )
        self.assertEqual(
            calculate_digest("abc", "sha1"),
            "a9993e364706816aba3e25717850c26c9cd0d89d",
        )
        self.assertEqual(
            calculate_digest("abc", "md5"),
            "900150983cd24fb0d6963f7d28e17f72",
        )

    def test_hash_identification(self):
        self.assertEqual(identify_hash("a" * 32), ["MD5", "NTLM"])
        self.assertEqual(identify_hash("a" * 40), ["SHA-1"])
        self.assertEqual(identify_hash("a" * 64), ["SHA-256"])
        self.assertEqual(identify_hash("$2b$12$" + "a" * 53), ["bcrypt"])
        self.assertEqual(identify_hash("$argon2id$v=19$m=8192,t=1,p=1$abc$def"), ["Argon2id"])
        self.assertEqual(identify_hash("not-a-hash"), [])

    def test_argon2_hash_and_verify(self):
        if importlib.util.find_spec("argon2") is None:
            self.skipTest("argon2-cffi is not installed")
        encoded = hash_password_argon2(
            "correct horse battery staple",
            time_cost=1,
            memory_cost=8192,
            parallelism=1,
        )
        self.assertTrue(verify_password_argon2("correct horse battery staple", encoded))
        self.assertFalse(verify_password_argon2("wrong", encoded))

        with tempfile.NamedTemporaryFile("w", encoding="utf-8") as wordlist:
            wordlist.write("not-the-password\ncorrect horse battery staple\n")
            wordlist.flush()
            audit = audit_password_hash(encoded, wordlist.name, max_candidates=10)
        self.assertTrue(audit["matched"])
        self.assertEqual(audit["candidate"], "correct horse battery staple")
        self.assertEqual(audit["tested"], 2)

    def test_bcrypt_hash_and_verify(self):
        if importlib.util.find_spec("bcrypt") is None:
            self.skipTest("bcrypt is not installed")
        encoded = hash_password_bcrypt("test password", rounds=4)
        self.assertTrue(verify_password_bcrypt("test password", encoded))
        self.assertFalse(verify_password_bcrypt("wrong", encoded))

    def test_automatic_md5_dictionary_recovery(self):
        result = crack_raw_digest("5d41402abc4b2a76b9719d911017c592")
        self.assertTrue(result["matched"])
        self.assertEqual(result["algorithm"], "MD5")
        self.assertEqual(result["candidate"], "hello")

    def test_automatic_sha_variants_recover_known_common_candidate(self):
        import hashlib

        for algorithm in ("sha1", "sha224", "sha256", "sha384", "sha512"):
            with self.subTest(algorithm=algorithm):
                digest = hashlib.new(algorithm, b"hello").hexdigest()
                result = crack_raw_digest(digest)
                self.assertTrue(result["matched"])
                self.assertEqual(result["candidate"], "hello")
                self.assertEqual(result["algorithm"], algorithm.upper().replace("SHA", "SHA-" , 1) if algorithm != "sha1" else "SHA-1")

    def test_sha256_common_symbol_suffix_mutation(self):
        import hashlib

        digest = hashlib.sha256(b"hello@").hexdigest()
        result = crack_raw_digest(digest)
        self.assertTrue(result["matched"])
        self.assertEqual(result["algorithm"], "SHA-256")
        self.assertEqual(result["candidate"], "hello@")
        self.assertEqual(result["source"], "built-in common mutations")

    def test_ntlm_md4_known_vector_and_recovery(self):
        digest = md4("password".encode("utf-16le")).hex()
        self.assertEqual(digest, "8846f7eaee8fb117ad06bdd830b7586c")
        result = crack_raw_digest(digest)
        self.assertTrue(result["matched"])
        self.assertEqual(result["algorithm"], "NTLM")
        self.assertEqual(result["candidate"], "password")

    def test_unknown_raw_digest_reports_no_match(self):
        result = crack_raw_digest("00000000000000000000000000000000", max_candidates=30)
        self.assertFalse(result["matched"])
        self.assertEqual(result["tested"], 30)

    def test_unsupported_digest(self):
        with self.assertRaises(ValueError):
            calculate_digest("abc", "sha3-256")


if __name__ == "__main__":
    unittest.main()
