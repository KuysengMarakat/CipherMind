
from plugins.base import Plugin

from classical.atbash import atbash_transform


class AtbashPlugin(Plugin):

    name = "Atbash"

    cost = 1

    # Check whether input is suitable for Atbash
    def detect(self, state):

        if not isinstance(state, str):

            return 0.0

        if not state.strip():

            return 0.0

        # Check for English alphabet characters
        letters = [
            char for char in state
            if char.isascii() and char.isalpha()
        ]

        if not letters:

            return 0.0

        # Suitable for testing, not confirmed Atbash
        return 0.5


    # Perform Atbash transformation
    def apply(self, state):

        if not isinstance(state, str):

            raise TypeError("Input must be text")

        result = atbash_transform(state)

        return result.encode("utf-8")


    # Explain the operation
    def explain(self, params=None):

        return "Transformed input using Atbash Cipher."
