
# Import Vigenere analysis tools
from classical.vigenere_analysis import (
    estimate_key_lengths,
    get_letters
)

# Import Kasiski examination
from classical.kasiski import kasiski_examination

# Import keyword recovery
from classical.vigenere_recovery import recover_vigenere_key

# Import the existing scoring system
from scoring.scorer import analyze_candidate


# Analyse encrypted Vigenere text
def analyze_vigenere(ciphertext, max_key_length=12):

    # Check input
    if not isinstance(ciphertext, str):
        raise TypeError("Input must be text")

    letters = get_letters(ciphertext)

    if len(letters) < 4:
        raise ValueError("Ciphertext is too short")

    # Keep the original input as bytes
    original_data = ciphertext.encode("utf-8")

    # STEP 1: Estimate key lengths using IOC
    ioc_results = estimate_key_lengths(
        ciphertext,
        max_key_length
    )

    # STEP 2: Estimate key lengths using Kasiski
    kasiski_results = kasiski_examination(
        ciphertext,
        max_key_length=max_key_length
    )

    # Collect possible key lengths
    possible_lengths = []

    # Add the top five IOC results
    for result in ioc_results[:5]:

        length = result["key_length"]

        if length not in possible_lengths:
            possible_lengths.append(length)

    # Add the top five Kasiski results
    for result in kasiski_results[:5]:

        length = result["key_length"]

        if length not in possible_lengths:
            possible_lengths.append(length)

    # Store IOC scores
    ioc_scores = {}

    for result in ioc_results:

        ioc_scores[result["key_length"]] = result["ioc"]

    # Store Kasiski scores
    kasiski_scores = {}

    for result in kasiski_results:

        kasiski_scores[result["key_length"]] = result["score"]

    # Store all possible candidates
    candidates = []

    # STEP 3: Recover possible keywords
    for key_length in possible_lengths:

        if key_length > len(letters) // 2:
            continue

        recovery = recover_vigenere_key(
            ciphertext,
            key_length
        )

        # Convert recovered plaintext into bytes
        plaintext = recovery["plaintext"]

        plaintext_bytes = plaintext.encode("utf-8")

        # STEP 4: Calculate candidate scores
        scores = analyze_candidate(
            original_data,
            plaintext_bytes
        )

        # Store candidate information
        candidate = {

            "key_length": key_length,

            "key": recovery["key"],

            "plaintext": plaintext,

            "printable_ratio": scores["printable_ratio"],

            "quadgram_score": scores["quadgram_score"],

            "entropy_change": scores["entropy_change"],

            "ioc_score": ioc_scores.get(
                key_length,
                0
            ),

            "kasiski_score": kasiski_scores.get(
                key_length,
                0
            )

        }

        candidates.append(candidate)

    # STEP 5: Rank candidates using Quadgram scores
    candidates.sort(
        key=lambda item: (
            item["quadgram_score"]
            if item["quadgram_score"] is not None
            else float("-inf")
        ),
        reverse=True
    )

    # Return the analysis results
    return {

        "ioc_results": ioc_results,

        "kasiski_results": kasiski_results,

        "candidates": candidates

    }
