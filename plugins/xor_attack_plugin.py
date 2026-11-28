
from plugins.base import Plugin

from classical.xor_recovery import analyze_repeating_key_xor


class XorAttackPlugin(Plugin):

    name = "Automatic XOR Analysis"

    cost = 10

    # This plugin processes hexadecimal ciphertext
    input_mode = "hex"

    def __init__(self, max_key_length=12):

        self.max_key_length = max_key_length

        self.analysis = None

        self.best_candidate = None

    def convert_input(self, state):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        try:
            data = bytes.fromhex(state)

        except ValueError:
            raise ValueError("Input must be hexadecimal text")

        if len(data) < 4:
            raise ValueError("Ciphertext is too short")

        return data

    def detect(self, state):

        try:
            self.convert_input(state)
            return 0.5

        except (TypeError, ValueError):
            return 0.0

    def apply(self, state):

        ciphertext = self.convert_input(state)

        self.analysis = analyze_repeating_key_xor(
            ciphertext,
            max_key_length=self.max_key_length
        )

        if not self.analysis:
            raise ValueError("No XOR candidates found")

        self.best_candidate = self.analysis[0]

        return self.best_candidate["plaintext"]

    def explain(self, params=None):

        if self.best_candidate is None:
            return "XOR analysis has not been performed."

        key = self.best_candidate["key_hex"]

        key_length = self.best_candidate["key_length"]

        return (
            f"Automatic XOR analysis completed. "
            f"Recovered key (hex): {key}. "
            f"Estimated key length: {key_length}."
        )
