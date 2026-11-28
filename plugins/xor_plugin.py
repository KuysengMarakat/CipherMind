
# Import the base plugin
from plugins.base import Plugin

# Import XOR decryption
from classical.xor import xor_decrypt


class XorPlugin(Plugin):

    name = "XOR"

    cost = 2

    # Initialize the plugin with a key
    def __init__(self, key):

        if not isinstance(key, str):
            raise TypeError("Key must be text")

        if not key:
            raise ValueError("Key cannot be empty")

        self.key = key

        self.key_bytes = key.encode("utf-8")

        self.name = f"XOR (key={key})"


    # Check whether input is suitable
    def detect(self, state):

        if not isinstance(state, str):
            return 0.0

        if not state:
            return 0.0

        return 0.5


    # Perform XOR decryption
    def apply(self, state):

        if not isinstance(state, str):
            raise TypeError("Input must be text")

        # Convert input into bytes
        data = state.encode("utf-8")

        # Decrypt using the selected key
        result = xor_decrypt(
            data,
            self.key_bytes
        )

        return result


    # Explain the operation
    def explain(self, params=None):

        return (
            f"Decrypted using XOR "
            f"with key '{self.key}'."
        )


# Generate XOR plugins from possible keys
def create_xor_plugins(candidate_keys):

    plugins = []

    used_keys = set()

    for key in candidate_keys:

        plugin = XorPlugin(key)

        # Avoid duplicate keys
        if plugin.key_bytes in used_keys:
            continue

        plugins.append(plugin)

        used_keys.add(plugin.key_bytes)

    return plugins
