
import base64
import binascii

from plugins.base import Plugin


class Base64Plugin(Plugin):

    name = "Base64"

    cost = 1

    # Check whether input is valid Base64

    def detect(self, state):

        try:

            self._decode(state)

            return 0.95

        except (ValueError, TypeError):

            return 0.0


    # Perform Base64 decoding

    def apply(self, state):

        return self._decode(state)


    # Explain the operation

    def explain(self, params=None):

        return "Decoded input using Base64."


    # Internal decoding function

    def _decode(self, state):

        if not isinstance(state, str):

            raise TypeError("Input must be text")

        cleaned = "".join(state.split())

        if not cleaned:

            raise ValueError("Input cannot be empty")

        if len(cleaned) % 4 == 1:

            raise ValueError("Invalid Base64 length")

        if "=" in cleaned:

            if len(cleaned) % 4 != 0:

                raise ValueError("Invalid Base64 padding")

            padded = cleaned

        else:

            padding = (4 - len(cleaned) % 4) % 4

            padded = cleaned + ("=" * padding)


        decoded = base64.b64decode(
            padded,
            validate=True
        )


        encoded_again = base64.b64encode(
            decoded
        ).decode("ascii")


        if "=" in cleaned:

            valid = encoded_again == cleaned

        else:

            valid = encoded_again.rstrip("=") == cleaned


        if not valid:

            raise ValueError("Invalid Base64 representation")


        return decoded
