
# Import the base plugin
from plugins.base import Plugin

# Import the Vigenere algorithm
from classical.vigenere import vigenere_decrypt
from classical.vigenere import validate_key


class VigenerePlugin(Plugin):

    cost = 1

    # Initialize the plugin with a keyword
    def __init__(self, key):

        self.key = validate_key(key)

        self.name = f"Vigenere (key={self.key})"


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

        # Input is suitable for testing
        return 0.5


    # Perform Vigenere decryption
    def apply(self, state):

        result = vigenere_decrypt(
            state,
            self.key
        )

        return result.encode("utf-8")


    # Explain the operation
    def explain(self, params=None):

        return (
            f"Decrypted using Vigenere Cipher "
            f"with keyword '{self.key}'."
        )


# Generate plugins from possible keywords
def create_vigenere_plugins(candidate_keys):

    plugins = []

    used_keys = set()

    # Create one plugin for each keyword
    for key in candidate_keys:

        normalized_key = validate_key(key)

        # Avoid duplicate keywords
        if normalized_key in used_keys:
            continue

        plugin = VigenerePlugin(normalized_key)

        plugins.append(plugin)

        used_keys.add(normalized_key)

    return plugins
