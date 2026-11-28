
from plugins.base import Plugin


class HexPlugin(Plugin):

    name = "Hexadecimal"

    cost = 1

    # This plugin processes hexadecimal input
    input_mode = "hex"

    def detect(self, state):

        try:
            self._decode(state)
            return 0.95

        except (ValueError, TypeError):
            return 0.0

    def apply(self, state):

        return self._decode(state)

    def explain(self, params=None):

        return "Decoded input using Hexadecimal."

    def _decode(self, state):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        cleaned = "".join(state.split())

        if not cleaned:
            raise ValueError("Input cannot be empty")

        if len(cleaned) % 2 != 0:
            raise ValueError("Invalid hexadecimal length")

        for character in cleaned:

            if character not in "0123456789abcdefABCDEF":
                raise ValueError("Invalid hexadecimal character")

        return bytes.fromhex(cleaned)
