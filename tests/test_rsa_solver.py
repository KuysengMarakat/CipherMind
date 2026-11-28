"""RSA values pasted as text must be found and weak keys solved."""

import base64
import contextlib
import io
import random
import unittest

from main import analyze_once, build_parser
from modern.rsa_solver import parse_rsa_values, looks_like_rsa, solve_rsa

MESSAGE = b"CTF{rsa_is_fun}"
M = int.from_bytes(MESSAGE, "big")


def is_prime(n):
    """Miller-Rabin primality test (enough for test keys)."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def next_prime(x):
    x |= 1
    while not is_prime(x):
        x += 2
    return x


def random_prime(bits, rng):
    return next_prime(rng.getrandbits(bits) | (1 << (bits - 1)))


def solved_messages(text):
    return [row["plaintext"] for row in solve_rsa(text) if row["plaintext"]]


class RsaParsingTests(unittest.TestCase):
    def test_parse_single_line_and_hex(self):
        keys = parse_rsa_values("n=0x1f, e = 3, c: 8")
        self.assertEqual(keys, [{"n": 31, "e": 3, "c": 8}])

    def test_parse_numbered_keys_with_shared_e(self):
        keys = parse_rsa_values("n1 = 15\nn2 = 21\ne = 65537\nc1 = 2\nc2 = 4")
        self.assertEqual(len(keys), 2)
        self.assertEqual(keys[1], {"n": 21, "e": 65537, "c": 4})

    def test_normal_text_is_not_rsa(self):
        self.assertFalse(looks_like_rsa("the secret meeting is at dawn"))


class RsaWeaknessTests(unittest.TestCase):
    def setUp(self):
        self.rng = random.Random(2026)

    def test_small_exponent(self):
        n = random_prime(512, self.rng) * random_prime(512, self.rng)
        text = f"n = {n}\ne = 3\nc = {pow(M, 3, n)}"
        self.assertIn(MESSAGE, solved_messages(text))

    def test_close_primes(self):
        p = random_prime(512, self.rng)
        q = next_prime(p + 2 ** 200)
        n = p * q
        text = f"n = {n}\ne = 65537\nc = {pow(M, 65537, n)}"
        self.assertIn(MESSAGE, solved_messages(text))

    def test_shared_prime(self):
        p = random_prime(512, self.rng)
        n1 = p * random_prime(512, self.rng)
        n2 = p * random_prime(512, self.rng)
        text = (
            f"n1 = {n1}\nn2 = {n2}\ne = 65537\n"
            f"c1 = {pow(M, 65537, n1)}\nc2 = {pow(M, 65537, n2)}"
        )
        self.assertIn(MESSAGE, solved_messages(text))

    def test_strong_key_is_not_solved(self):
        n = random_prime(512, self.rng) * random_prime(512, self.rng)
        text = f"n = {n}\ne = 65537\nc = {pow(M, 65537, n)}"
        self.assertEqual(solved_messages(text), [])

    def test_rsa_then_base64_from_paste_input(self):
        n = random_prime(512, self.rng) * random_prime(512, self.rng)
        m = int.from_bytes(base64.b64encode(b"CTF{rsa_then_base64}"), "big")
        output = io.StringIO()
        args = build_parser().parse_args(["--once"])
        with contextlib.redirect_stdout(output):
            analyze_once(f"n={n}, e=3, c={pow(m, 3, n)}", args)
        rendered = output.getvalue()
        self.assertIn("RSA WEAKNESS CHECKS", rendered)
        self.assertIn("CTF{rsa_then_base64}", rendered)
        self.assertIn("STATUS          : VERIFIED", rendered)


if __name__ == "__main__":
    unittest.main()
