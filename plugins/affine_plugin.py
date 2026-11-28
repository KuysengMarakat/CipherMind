
# Import the base plugin
from plugins.base import Plugin

# Import Affine decryption
from classical.affine import (
    affine_decrypt,
    VALID_A_VALUES
)


class AffinePlugin(Plugin):

    cost = 1

    # Store the two Affine keys
    def __init__(self, a, b):

        self.a = a
        self.b = b

        self.name = f"Affine (a={a}, b={b})"


    # Check whether input contains English letters
    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        for char in state:

            if char.isascii() and char.isalpha():

                return 0.5

        return 0.0


    # Decrypt using the selected keys
    def apply(self, state):

        plaintext = affine_decrypt(
            state,
            self.a,
            self.b
        )

        return plaintext.encode("utf-8")


    # Explain the operation
    def explain(self, params=None):

        return (
            f"Decrypted using Affine Cipher "
            f"with a={self.a} and b={self.b}."
        )


# Generate all possible Affine plugins
def create_affine_plugins():

    plugins = []

    # Try every valid multiplication key
    for a in VALID_A_VALUES:

        # Try every addition key
        for b in range(26):

            plugin = AffinePlugin(a, b)

            plugins.append(plugin)

    return plugins
