
from plugins.base import Plugin
from classical.caesar import caesar_decrypt


class CaesarPlugin(Plugin):

    name = "Caesar"

    cost = 1

    # Create a plugin for a specific shift
    def __init__(self, shift=0):

        self.shift = shift

        self.name = f"Caesar (Shift {shift})"


    # Check whether input is suitable for Caesar
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

        # This means the input is worth testing,
        # not that Caesar encryption is confirmed.
        return 0.5


    # Perform Caesar decryption
    def apply(self, state):

        if not isinstance(state, str):

            raise TypeError("Input must be text")

        # Decrypt using the selected shift
        result = caesar_decrypt(
            state,
            self.shift
        )

        # Return bytes like our Base64 plugin
        return result.encode("utf-8")


    # Explain the operation
    def explain(self, params=None):

        return (
            f"Decrypted using Caesar Cipher "
            f"with shift {self.shift}."
        )


# Generate all 26 possible Caesar plugins
def create_caesar_plugins():

    plugins = []

    for shift in range(26):

        plugin = CaesarPlugin(shift)

        plugins.append(plugin)

    return plugins
