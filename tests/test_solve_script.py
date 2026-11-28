"""Generated solve scripts must run on their own and print the answer."""

import base64
import subprocess
import sys
import unittest
import urllib.parse

from classical.vigenere import vigenere_encrypt
from classical.xor import xor_encrypt
from core.search import SearchStep, run_search
from reporting.solve_script import build_solve_script

PLAIN = "the secret meeting is at dawn near the old bridge"


def step(name, **params):
    return SearchStep(plugin=name, explanation="", confidence=1.0, params=params)


def run_script(source):
    """Run a script in a fresh Python process and return what it prints."""
    completed = subprocess.run(
        [sys.executable, "-I", "-c", source],
        capture_output=True, text=True, timeout=30, check=True,
    )
    return completed.stdout.rstrip("\n")


def caesar_encrypt(text, shift):
    return "".join(
        chr((ord(c) - 97 + shift) % 26 + 97) if c.islower() else c for c in text
    )


def affine_encrypt(text, a, b):
    return "".join(
        chr((a * (ord(c) - 97) + b) % 26 + 97) if c.islower() else c for c in text
    )


def atbash(text):
    return "".join(chr(122 - (ord(c) - 97)) if c.islower() else c for c in text)


class SolveScriptTemplateTests(unittest.TestCase):
    def check(self, ciphertext, steps, expected=PLAIN):
        script = build_solve_script(ciphertext, steps)
        self.assertEqual(run_script(script), expected)

    def test_encodings(self):
        data = PLAIN.encode()
        self.check(data.hex(), [step("Hexadecimal")])
        self.check(base64.b64encode(data).decode(), [step("Base64")])
        self.check(base64.b32encode(data).decode(), [step("Base32")])
        self.check(base64.b85encode(data).decode(), [step("Base85")])
        self.check(" ".join(f"{b:08b}" for b in data), [step("Binary")])
        self.check(" ".join(f"{b:o}" for b in data), [step("Octal")])
        self.check(" ".join(str(b) for b in data), [step("Decimal")])
        self.check(urllib.parse.quote(PLAIN), [step("URL encoding")])
        self.check("&#116;&#104;&#101; secret", [step("HTML entities")], "the secret")

    def test_base58_and_morse(self):
        self.check("JxF12TrwUP45BMd", [step("Base58")], "Hello World")
        self.check(".... .. / - .... . .-. .", [step("Morse code")], "HI THERE")

    def test_classical_ciphers(self):
        self.check(caesar_encrypt(PLAIN, 7), [step("Caesar (Shift 7)", shift=7)])
        self.check(atbash(PLAIN), [step("Atbash")])
        self.check(
            affine_encrypt(PLAIN, 5, 8), [step("Affine (a=5, b=8)", a=5, b=8)]
        )
        self.check(
            vigenere_encrypt(PLAIN, "LEMON"),
            [step("Vigenere Automatic Analysis", key="LEMON")],
        )

    def test_xor(self):
        ciphertext = xor_encrypt(PLAIN.encode(), b"key").hex()
        self.check(ciphertext, [step("Automatic XOR Analysis", key_hex="6b6579")])

    def test_substitution(self):
        key = "QWERTYUIOPASDFGHJKLZXCVBNM"
        ciphertext = "".join(
            key[ord(c) - 97].lower() if c.islower() else c for c in PLAIN
        )
        self.check(
            ciphertext, [step("Automatic Substitution Analysis", key=key)]
        )


class SolveScriptFromSearchTests(unittest.TestCase):
    def test_script_reproduces_search_result(self):
        ciphertext = base64.b32encode(atbash(PLAIN).encode()).decode()
        result = run_search(ciphertext, max_depth=4, max_states=2000)
        best = result["results"][0]
        script = build_solve_script(ciphertext, best.steps)
        self.assertEqual(run_script(script), best.text)
        self.assertEqual(best.text, PLAIN)


if __name__ == "__main__":
    unittest.main()
