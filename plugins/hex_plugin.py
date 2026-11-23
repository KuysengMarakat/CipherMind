
from plugins.base import Plugin


class HexPlugin(Plugin):

    name = "Hexadecimal"

    cost = 1


    # Check whether input is valid hexadecimal

    def detect(self, state):

        try:

            self._decode(state)

            return 0.95

        except (ValueError, TypeError):

            return 0.0


    # Perform hexadecimal decoding

    def apply(self, state):

        return self._decode(state)


    # Explain the operation

    def explain(self, params=None):

        return "Decoded input using Hexadecimal."


    # Internal decoding function

    def _decode(self, state):

        # Check input type

        if not isinstance(state, str):

            raise TypeError("Input must be text")


        # Remove spaces and new lines

        cleaned = "".join(state.split())


        # Check empty input

        if not cleaned:

            raise ValueError("Input cannot be empty")


        # Each byte needs two hexadecimal characters

        if len(cleaned) % 2 != 0:

            raise ValueError("Invalid hexadecimal length")


        # Check hexadecimal characters

        for character in cleaned:

            if character not in "0123456789abcdefABCDEF":

                raise ValueError("Invalid hexadecimal character")


        # Convert hexadecimal into bytes

        decoded = bytes.fromhex(cleaned)


        return decoded
