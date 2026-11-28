import base64
import unittest

from core.search import run_search


def rot13(text):
    result = []
    for char in text:
        if "a" <= char <= "z":
            result.append(chr((ord(char) - 97 + 13) % 26 + 97))
        elif "A" <= char <= "Z":
            result.append(chr((ord(char) - 65 + 13) % 26 + 65))
        else:
            result.append(char)
    return "".join(result)


class SearchTests(unittest.TestCase):
    def test_search_recovers_three_layers(self):
        plaintext = "CTF{small_test}"
        layer_one = rot13(plaintext)
        layer_two = base64.b64encode(layer_one.encode()).decode()
        ciphertext = layer_two.encode().hex()

        result = run_search(
            ciphertext,
            max_depth=3,
            beam_width=20,
            max_states=100,
            time_budget=5,
            flag_pattern=r"CTF\{[a-z_]+\}",
        )
        self.assertTrue(any(item.verified for item in result["results"]))
        self.assertEqual(
            next(item.text for item in result["results"] if item.verified),
            plaintext,
        )

    def test_proposal_worked_example_leetspeak_flag(self):
        # Worked example from the project proposal (Section 2.3):
        # hex -> Base64 -> ROT13 with a leetspeak flag.
        ciphertext = (
            "5545645465336b3062444e6c4e563877"
            "633139774d48457a66513d3d"
        )

        result = run_search(
            ciphertext,
            max_depth=4,
            flag_pattern=r"CTF\{[^}]+\}",
        )

        best = result["results"][0]
        self.assertTrue(best.verified)
        self.assertEqual(best.text, "CTF{l4y3r5_0f_c0d3}")
        self.assertEqual(
            [step.plugin for step in best.steps],
            ["Hexadecimal", "Base64", "Caesar (Shift 13)"],
        )

    def test_search_rejects_bad_limits(self):
        with self.assertRaises(ValueError):
            run_search("hello", max_depth=0)


if __name__ == "__main__":
    unittest.main()
