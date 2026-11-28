
# Import XOR encryption
from classical.xor import xor_encrypt

# Import single-byte XOR attack
from classical.xor_analysis import analyze_single_byte_xor


# Main test function
def main():

    print("====================================")
    print("     SINGLE-BYTE XOR ATTACK TEST")
    print("====================================")

    # STEP 1: Original English message
    plaintext = (
        b"Cryptography helps protect messages and information. "
        b"Computer security uses encryption to protect sensitive data. "
        b"Students should understand how encryption and decryption work. "
        b"XOR is an important operation in cryptography and security. "
        b"Frequency analysis can help recover unknown encryption keys. "
        b"Testing different keys allows us to discover readable plaintext."
    )

    # STEP 2: Secret key (one byte)
    secret_key = 0x42

    # Convert key into bytes
    key = bytes([secret_key])

    # STEP 3: Encrypt the original message
    ciphertext = xor_encrypt(
        plaintext,
        key
    )

    print("\nOriginal message:", plaintext.decode())

    print("Secret key:", hex(secret_key))

    print("Ciphertext:", ciphertext.hex())

    # STEP 4: Attack the ciphertext
    print("\n===== TRYING ALL 256 KEYS =====")

    candidates = analyze_single_byte_xor(
        ciphertext,
        top_n=5
    )

    # STEP 5: Display the top five candidates
    for rank, candidate in enumerate(
        candidates,
        start=1
    ):

        print("\nRank:", rank)

        print("Recovered key:", candidate["key"])

        print("Key in hex:", candidate["key_hex"])

        print(
            "Printable ratio:",
            candidate["printable_ratio"] * 100,
            "%"
        )

        print(
            "English score:",
            candidate["english_score"]
        )

        print(
            "Recovered plaintext:",
            candidate["plaintext"].decode(
                "utf-8",
                errors="replace"
            )
        )

    # STEP 6: Verify the recovered key
    best_candidate = candidates[0]

    print("\n====================================")
    print("             TEST RESULT")
    print("====================================")

    print(
        "Expected key:",
        hex(secret_key)
    )

    print(
        "Recovered key:",
        best_candidate["key_hex"]
    )

    if best_candidate["key"] == secret_key:

        print("Correct key recovered: YES")

        print("TEST PASSED")

    else:

        print("Correct key recovered: NO")

        print("TEST FAILED")


# Run the test
if __name__ == "__main__":

    main()
