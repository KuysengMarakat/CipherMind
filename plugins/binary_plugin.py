
from plugins.base import Plugin


class BinaryPlugin(Plugin):

    name = "Binary"

    cost = 1

    input_mode = "binary"

    # ======================================
    # 1. Detect Binary
    # ======================================

    def detect(self, state):

        try:

            self._decode(state)

            return 0.95

        except (ValueError, TypeError):

            return 0.0

    # ======================================
    # 2. Decode Binary
    # ======================================

    def apply(self, state):

        return self._decode(state)

    # ======================================
    # 3. Explain Operation
    # ======================================

    def explain(self, params=None):

        return "Decoded input using Binary."

    # ======================================
    # 4. Internal Decoder
    # ======================================

    def _decode(self, state):

        if not isinstance(state, str):

            raise TypeError("Input must be text")

        cleaned = "".join(state.split())

        if not cleaned:

            raise ValueError("Input cannot be empty")

        for character in cleaned:

            if character not in "01":

                raise ValueError("Invalid binary character")

        if len(cleaned) % 8 != 0:

            raise ValueError(
                "Binary length must be a multiple of 8"
            )

        byte_values = []

        for i in range(0, len(cleaned), 8):

            byte_string = cleaned[i:i + 8]

            byte_value = int(byte_string, 2)

            byte_values.append(byte_value)

        return bytes(byte_values)
