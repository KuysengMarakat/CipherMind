
# English letter frequencies (A to Z)
ENGLISH_FREQUENCIES = [
    0.08167, 0.01492, 0.02782, 0.04253,
    0.12702, 0.02228, 0.02015, 0.06094,
    0.06966, 0.00153, 0.00772, 0.04025,
    0.02406, 0.06749, 0.07507, 0.01929,
    0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150,
    0.01974, 0.00074
]


# Calculate how many bytes are readable
def calculate_printable_ratio(data):

    if len(data) == 0:
        return 0.0

    printable_count = 0

    for byte in data:

        if 32 <= byte <= 126 or byte in (9, 10, 13):

            printable_count += 1

    return printable_count / len(data)


# Calculate how closely text matches English frequencies
def calculate_english_score(data):

    # Count each English letter
    frequencies = [0] * 26

    total_letters = 0

    for byte in data:

        # Uppercase letters
        if 65 <= byte <= 90:

            position = byte - 65

        # Lowercase letters
        elif 97 <= byte <= 122:

            position = byte - 97

        else:
            continue

        frequencies[position] += 1

        total_letters += 1

    if total_letters == 0:
        return None

    # Calculate Chi-Squared score
    score = 0.0

    for index in range(26):

        expected = (
            total_letters * ENGLISH_FREQUENCIES[index]
        )

        actual = frequencies[index]

        score += (
            (actual - expected) ** 2
        ) / expected

    return score


# Try one possible XOR key
def decrypt_single_byte_xor(ciphertext, key):

    result = []

    for byte in ciphertext:

        decrypted_byte = byte ^ key

        result.append(decrypted_byte)

    return bytes(result)


# Try all 256 possible single-byte keys
def analyze_single_byte_xor(ciphertext, top_n=10):

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not ciphertext:
        raise ValueError("Ciphertext cannot be empty")

    if not isinstance(top_n, int) or top_n < 1:
        raise ValueError("top_n must be a positive integer")

    candidates = []

    # Try keys from 0 to 255
    for key in range(256):

        # Decrypt using the current key
        plaintext = decrypt_single_byte_xor(
            ciphertext,
            key
        )

        # Calculate readability
        printable_ratio = calculate_printable_ratio(
            plaintext
        )

        # Calculate English frequency score
        english_score = calculate_english_score(
            plaintext
        )

        # Store the candidate
        candidate = {

            "key": key,

            "key_hex": hex(key),

            "plaintext": plaintext,

            "printable_ratio": round(
                printable_ratio,
                4
            ),

            "english_score": (
                round(english_score, 4)
                if english_score is not None
                else None
            )

        }

        candidates.append(candidate)

    # Rank candidates
    def ranking_score(candidate):

        english_score = candidate["english_score"]

        if english_score is None:
            english_score = float("inf")

        return (
            -candidate["printable_ratio"],
            english_score
        )

    candidates.sort(key=ranking_score)

    # Return the best candidates
    return candidates[:top_n]
