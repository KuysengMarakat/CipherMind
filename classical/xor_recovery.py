
# Import XOR decryption
from classical.xor import xor_decrypt

# Import single-byte XOR analysis
from classical.xor_analysis import (
    analyze_single_byte_xor,
    calculate_printable_ratio,
    calculate_english_score
)

# Import CipherMind scoring system
from scoring.scorer import analyze_candidate


# ==========================================
# 1. Normalize Repeating XOR Key
# ==========================================

def normalize_repeating_key(key):

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if not key:
        raise ValueError("Key cannot be empty")

    # Try possible shorter key lengths
    for length in range(1, len(key) + 1):

        # The key must divide evenly
        if len(key) % length != 0:
            continue

        # Extract possible shorter key
        short_key = key[:length]

        # Check whether it reproduces the original key
        repeated_key = short_key * (len(key) // length)

        if repeated_key == key:
            return short_key

    return key


# ==========================================
# 2. Calculate Hamming Distance
# ==========================================

def calculate_hamming_distance(first, second):

    if len(first) != len(second):
        raise ValueError("Both blocks must have equal length")

    distance = 0

    for index in range(len(first)):

        difference = first[index] ^ second[index]

        distance += bin(difference).count("1")

    return distance


# ==========================================
# 3. Estimate Possible Key Lengths
# ==========================================

def estimate_xor_key_lengths(ciphertext, max_key_length=12):

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not isinstance(max_key_length, int) or max_key_length < 1:
        raise ValueError("Maximum key length must be positive")

    if len(ciphertext) < 4:
        return []

    results = []

    # Try different possible key lengths
    for key_length in range(1, max_key_length + 1):

        if key_length * 2 > len(ciphertext):
            continue

        blocks = []

        # Divide ciphertext into equal-sized blocks
        for position in range(
            0,
            len(ciphertext) - key_length + 1,
            key_length
        ):

            block = ciphertext[position:position + key_length]

            blocks.append(block)

            if len(blocks) == 4:
                break

        total_distance = 0
        comparisons = 0

        # Compare every pair of blocks
        for first_index in range(len(blocks)):

            for second_index in range(
                first_index + 1,
                len(blocks)
            ):

                distance = calculate_hamming_distance(
                    blocks[first_index],
                    blocks[second_index]
                )

                total_distance += distance / key_length

                comparisons += 1

        if comparisons == 0:
            continue

        average_distance = total_distance / comparisons

        results.append({
            "key_length": key_length,
            "distance": round(average_distance, 4)
        })

    # Smaller distances are more promising
    results.sort(
        key=lambda item: item["distance"]
    )

    return results


# ==========================================
# 4. Recover Repeating XOR Key
# ==========================================

def recover_repeating_xor_key(ciphertext, key_length):

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not isinstance(key_length, int) or key_length < 1:
        raise ValueError("Key length must be positive")

    if key_length * 2 > len(ciphertext):
        raise ValueError("Ciphertext is too short for this key length")

    key_values = []

    # Recover each individual key byte
    for position in range(key_length):

        group = ciphertext[position::key_length]

        candidates = analyze_single_byte_xor(
            group,
            top_n=1
        )

        if not candidates:
            raise ValueError("Unable to recover XOR key byte")

        best_candidate = candidates[0]

        key_values.append(best_candidate["key"])

    # Reconstruct the complete key
    recovered_key = bytes(key_values)

    # Normalize repeated key
    key = normalize_repeating_key(recovered_key)

    # Decrypt using normalized key
    plaintext = xor_decrypt(
        ciphertext,
        key
    )

    return {

        "key": key,

        "key_hex": key.hex(),

        "key_length": len(key),

        "estimated_key_length": key_length,

        "plaintext": plaintext,

        "printable_ratio": calculate_printable_ratio(
            plaintext
        ),

        "english_score": calculate_english_score(
            plaintext
        )

    }


# ==========================================
# 5. Automatically Analyze Repeating XOR
# ==========================================

def analyze_repeating_key_xor(
    ciphertext,
    max_key_length=12,
    top_key_lengths=5
):

    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")

    if not isinstance(top_key_lengths, int) or top_key_lengths < 1:
        raise ValueError("top_key_lengths must be positive")

    # STEP 1: Estimate possible key lengths
    key_lengths = estimate_xor_key_lengths(
        ciphertext,
        max_key_length
    )

    # Select promising key lengths
    key_lengths = key_lengths[:top_key_lengths]

    candidates = []

    # STEP 2: Recover possible keys
    for item in key_lengths:

        estimated_length = item["key_length"]

        result = recover_repeating_xor_key(
            ciphertext,
            estimated_length
        )

        # STEP 3: Evaluate complete plaintext
        scores = analyze_candidate(
            ciphertext,
            result["plaintext"]
        )

        # Keep both key lengths
        result["estimated_key_length"] = estimated_length

        # Use normalized key length as the actual key length
        result["key_length"] = len(result["key"])

        result["distance"] = item["distance"]

        result["quality_score"] = scores["quality_score"]

        result["word_score"] = scores["word_score"]

        result["quadgram_score"] = scores["quadgram_score"]

        result["scores"] = scores

        candidates.append(result)

    # STEP 4: Rank complete plaintext candidates
    def ranking_score(candidate):

        quadgram = candidate["quadgram_score"]

        if quadgram is None:
            quadgram = float("-inf")

        return (
            candidate["quality_score"],
            candidate["printable_ratio"],
            quadgram,
            -candidate["distance"]
        )

    candidates.sort(
        key=ranking_score,
        reverse=True
    )

    return candidates
