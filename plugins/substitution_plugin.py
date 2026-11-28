
# Import the base plugin
from plugins.base import Plugin

# Import the substitution decryption algorithm
from classical.substitution import (
    substitution_decrypt,
    validate_key
)


class SubstitutionPlugin(Plugin):

    name = "Simple Substitution"

    cost = 2

    # Initialize the plugin with a substitution key
    def __init__(self, key):

        self.key = validate_key(key)

        self.name = "Substitution Cipher"


    # Check whether input is suitable
    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        if not state.strip():
            return 0.0

        # Check for English letters
        letters = [
            char for char in state
            if char.isascii() and char.isalpha()
        ]

        if not letters:
            return 0.0

        # Input is suitable for substitution analysis
        return 0.5


    # Perform substitution decryption
    def apply(self, state):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        # Decrypt using the provided key
        result = substitution_decrypt(
            state,
            self.key
        )

        # Return the result as bytes
        return result.encode("utf-8")


    # Explain the operation
    def explain(self, params=None):

        return (
            "Decrypted using Simple Substitution Cipher."
        )


# Create multiple substitution plugins
def create_substitution_plugins(candidate_keys):

    plugins = []

    used_keys = set()

    # Create one plugin for each possible key
    for key in candidate_keys:

        # Validate the key
        valid_key = validate_key(key)

        # Avoid duplicate keys
        if valid_key in used_keys:
            continue

        # Create the plugin
        plugin = SubstitutionPlugin(valid_key)

        plugins.append(plugin)

        used_keys.add(valid_key)

    return plugins
