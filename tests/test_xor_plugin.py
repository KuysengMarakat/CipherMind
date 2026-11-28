
from classical.xor import xor_encrypt
from plugins.registry import create_default_plugins


def normalize_key(key):

    for length in range(1, len(key) + 1):

        if len(key) % length == 0:

            short_key = key[:length]

            if short_key * (len(key) // length) == key:
                return short_key

    return key


def main():

    print("====================================")
    print("       CIPHERMIND XOR PLUGIN")
    print("====================================")

    # Original plaintext
    plaintext = (
        b"Cryptography helps protect messages and information. "
        b"Computer security uses encryption to protect sensitive data. "
        b"Students should understand encryption and decryption. "
        b"XOR is an important operation in cryptography. "
        b"Frequency analysis can help recover unknown encryption keys. "
        b"Security researchers study encryption weaknesses. "
        b"Testing different keys helps discover readable plaintext. "
        b"Cryptography protects communication and sensitive information."
    )

    # Secret key
    secret_key = b"LEMON"

    # Encrypt message
    ciphertext = xor_encrypt(
        plaintext,
        secret_key
    )

    # Convert ciphertext into hexadecimal input
    input_data = ciphertext.hex()

    print("\nOriginal key:", secret_key.decode())

    # Load registered plugins
    plugins = create_default_plugins()

    # Find XOR plugin
    xor_plugin = next(
        (
            plugin for plugin in plugins
            if plugin.name == "Automatic XOR Analysis"
        ),
        None
    )

    if xor_plugin is None:

        print("\nERROR: XOR plugin is not registered.")

        return

    print("\nXOR plugin registered: YES")

    # Check detection
    confidence = xor_plugin.detect(input_data)

    print("Detection score:", confidence)

    if confidence <= 0:

        print("\nTEST FAILED: Plugin did not detect input.")

        return

    # Execute automatic XOR attack
    recovered_plaintext = xor_plugin.apply(input_data)

    candidate = xor_plugin.best_candidate

    recovered_key = candidate["key"]

    normalized_key = normalize_key(recovered_key)

    # Display results
    print("\n===== RECOVERY RESULTS =====")

    print(
        "Recovered key:",
        recovered_key.decode("ascii", errors="replace")
    )

    print(
        "Normalized key:",
        normalized_key.decode("ascii", errors="replace")
    )

    print(
        "Estimated key length:",
        candidate["key_length"]
    )

    print(
        "Printable ratio:",
        candidate["printable_ratio"] * 100,
        "%"
    )

    print("\nRecovered plaintext:")

    print(
        recovered_plaintext.decode(
            "utf-8",
            errors="replace"
        )
    )

    print("\nExplanation:", xor_plugin.explain())

    # Verify
    key_correct = normalized_key == secret_key

    plaintext_correct = recovered_plaintext == plaintext

    print("\n===== TEST RESULT =====")

    print("Correct key:", key_correct)

    print("Correct plaintext:", plaintext_correct)

    if key_correct and plaintext_correct:

        print("\nTEST PASSED")

    else:

        print("\nTEST FAILED")


if __name__ == "__main__":

    main()
