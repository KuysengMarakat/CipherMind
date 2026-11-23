
from plugins.base import Plugin


class BinaryPlugin(Plugin):

    name = "Binary"

    cost = 1


    # Check whether input is valid binary

    def detect(self, state):

        try:

            self._decode(state)

            return 0.95

        except (ValueError, TypeError):

            return 0.0


    # Perform binary decoding

    def apply(self, state):

        return self._decode(state)


    # Explain the operation

    def explain(self, params=None):

        return "Decoded input using Binary."


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


        # Binary only allows 0 and 1

        for character in cleaned:

            if character not in "01":

                raise ValueError("Invalid binary character")


        # Each byte must contain 8 bits

        if len(cleaned) % 8 != 0:

            raise ValueError("Binary length must be a multiple of 8")


        # Convert binary into bytes

        byte_values = []

        for i in range(0, len(cleaned), 8):

            byte_string = cleaned[i:i + 8]

            byte_value = int(byte_string, 2)

            byte_values.append(byte_value)


        # Convert list of integers into bytes

        decoded = bytes(byte_values)


        return decoded
