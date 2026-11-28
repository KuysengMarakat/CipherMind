
# Import XOR encryption
from classical.xor import xor_encrypt

# Import repeating-key XOR recovery
from classical.xor_recovery import (
    recover_repeating_xor_key
)


def main():

    print("======================================")
    print("    REPEATING-KEY XOR RECOVERY TEST")
    print("======================================")

    # STEP 1: Original message
    plaintext = (
        b"Cryptography is the study of methods "
        b"used to protect information. "
        b"Encryption converts readable messages "
        b"into unreadable data. "

        b"Computer security uses cryptographic "
        b"algorithms to protect communication. "
        b"Students should understand how encryption "
        b"and decryption work. "

        b"XOR is a simple but important operation "
        b"in cryptography. "
        b"Repeating key encryption uses the same "
        b"secret key again and again. "

        b"Frequency analysis can help discover "
        b"unknown encryption keys. "
        b"Careful testing helps us understand "
        b"how cryptographic attacks work. "

        b"Security researchers study these methods "
        b"to identify weaknesses and improve "
        b"the protection of sensitive information."
    )

    # STEP 2: Secret key
    secret_key = b"LEMON"

    # STEP 3: Encrypt the message
    ciphertext = xor_encrypt(
        plaintext,
        secret_key
    )

    print("\nOriginal message:")
    print(plaintext.decode())

    print("\nSecret key:", secret_key.decode())

    print("\nCiphertext (hex):")
    print(ciphertext.hex())

    # STEP 4: Recover the key
    # We provide the key length for this first test.
    recovered = recover_repeating_xor_key(
        ciphertext,
        key_length=len(secret_key)
    )

    # STEP 5: Display recovered information
    print("\n===== RECOVERY RESULTS =====")

    print(
        "Recovered key:",
        recovered["key"].decode("ascii")
    )

    print(
        "Recovered key (hex):",
        recovered["key_hex"]
    )

    print(
        "Printable ratio:",
        recovered["printable_ratio"] * 100,
        "%"
    )

    print("\nRecovered plaintext:")

    print(
        recovered["plaintext"].decode(
            "utf-8",
            errors="replace"
        )
    )

    # STEP 6: Verify the result
    print("\n===== TEST RESULT =====")

    key_correct = recovered["key"] == secret_key

    plaintext_correct = (
        recovered["plaintext"] == plaintext
    )

    print("Expected key:", secret_key.decode())

    print(
        "Recovered key:",
        recovered["key"].decode("ascii")
    )

    print("Key recovered:", key_correct)

    print("Plaintext recovered:", plaintext_correct)

    if key_correct and plaintext_correct:

        print("\nTEST PASSED")

    else:

        print("\nTEST FAILED")


# Run the program
if __name__ == "__main__":

    main()
