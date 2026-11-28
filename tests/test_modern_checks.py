import unittest
from modern.rsa_checks import integer_nth_root, small_exponent_root, fermat_factor, shared_factor
from modern.hash_identifier import identify_hash
from modern.aes_checks import find_repeated_blocks, looks_like_ecb


class ModernCheckTests(unittest.TestCase):
    def test_integer_root_and_small_exponent(self):
        self.assertEqual(integer_nth_root(27, 3), 3)
        self.assertEqual(small_exponent_root(27, 3), 3)
        self.assertIsNone(small_exponent_root(28, 3))

    def test_fermat_factorisation(self):
        self.assertEqual(fermat_factor(5959), (59, 101))

    def test_shared_factor(self):
        self.assertEqual(shared_factor(11 * 13, 11 * 17), 11)
        self.assertIsNone(shared_factor(13 * 17, 19 * 23))

    def test_hash_identification_is_heuristic(self):
        self.assertEqual(identify_hash("a" * 32), ["MD5", "NTLM"])
        self.assertEqual(identify_hash("not-a-hash"), [])

    def test_repeated_aes_blocks(self):
        block = b"A" * 16
        repeated = block + block + b"B" * 16
        self.assertEqual(find_repeated_blocks(repeated), {block.hex(): 2})
        self.assertTrue(looks_like_ecb(repeated))


if __name__ == "__main__":
    unittest.main()
