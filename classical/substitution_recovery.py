
# Import random for generating different keys
import random

# Import substitution decryption
from classical.substitution import substitution_decrypt

# Import frequency analysis
from classical.substitution_analysis import (
    estimate_substitution_key
)

# Import our existing scoring system
from scoring.scorer import QUADGRAM_SCORES, FLOOR_SCORE

from scoring.quadgram_score import calculate_quadgram_score


# Calculate the English score of a possible key
def calculate_key_score(ciphertext, key):

    # Decrypt using the current key
    plaintext = substitution_decrypt(
        ciphertext,
        key
    )

    # Only the quadgram score is needed here, so compute just that.
    # (This runs thousands of times, so skipping the other scores
    # makes the attack several times faster.)
    score = calculate_quadgram_score(
        plaintext.encode("utf-8"),
        QUADGRAM_SCORES,
        FLOOR_SCORE
    )

    if score is None:
        score = float("-inf")

    return score, plaintext


# Create a slightly different version of a key
def create_random_key(original_key, number_of_swaps=5):

    # Convert the key into a list
    key = list(original_key)

    # Swap two letters several times
    for _ in range(number_of_swaps):

        first = random.randint(0, 25)
        second = random.randint(0, 25)

        key[first], key[second] = (
            key[second],
            key[first]
        )

    # Convert the list back into text
    return "".join(key)


# Improve one substitution key
def improve_substitution_key(
    ciphertext,
    initial_key,
    max_rounds=10
):

    # Start with the initial key
    best_key = initial_key

    best_score, best_plaintext = calculate_key_score(
        ciphertext,
        best_key
    )

    rounds_completed = 0

    # Try improving the key
    for _ in range(max_rounds):

        improved_key = best_key
        improved_score = best_score
        improved_plaintext = best_plaintext

        # Try swapping two different letters
        for first in range(26):

            for second in range(first + 1, 26):

                new_key = list(best_key)

                new_key[first], new_key[second] = (
                    new_key[second],
                    new_key[first]
                )

                new_key = "".join(new_key)

                # Calculate the new score
                new_score, new_plaintext = calculate_key_score(
                    ciphertext,
                    new_key
                )

                # Keep the better key
                if new_score > improved_score:

                    improved_key = new_key
                    improved_score = new_score
                    improved_plaintext = new_plaintext

        # Stop if no improvement was found
        if improved_score <= best_score:
            break

        best_key = improved_key
        best_score = improved_score
        best_plaintext = improved_plaintext

        rounds_completed += 1

    return {

        "key": best_key,

        "plaintext": best_plaintext,

        "quadgram_score": best_score,

        "rounds_completed": rounds_completed

    }


# Automatically recover the substitution key
def recover_substitution(
    ciphertext,
    max_rounds=10,
    restarts=5,
    random_swaps=5,
    good_enough=-4.5
):
    # good_enough: stop early once a key gives text whose average
    # quadgram score is at least this high. Real English scores about
    # -4.1 on our data; wrong keys score about -5.5 or lower.

    if not isinstance(ciphertext, str):
        raise TypeError("Ciphertext must be text")

    if not ciphertext.strip():
        raise ValueError("Ciphertext cannot be empty")

    if not isinstance(restarts, int) or restarts < 1:
        raise ValueError("Restarts must be at least 1")

    if not isinstance(max_rounds, int) or max_rounds < 1:
        raise ValueError("Maximum rounds must be positive")

    if not isinstance(random_swaps, int) or random_swaps < 1:
        raise ValueError("Random swaps must be positive")

    # Step 1: Estimate an initial key
    initial_key = estimate_substitution_key(
        ciphertext
    )

    best_result = None

    # Step 2: Try multiple starting keys
    for attempt in range(restarts):

        if attempt == 0:

            # First attempt uses the frequency-based key
            starting_key = initial_key

        else:

            # Other attempts use slightly changed keys
            starting_key = create_random_key(
                initial_key,
                random_swaps
            )

        # Step 3: Improve the starting key
        result = improve_substitution_key(
            ciphertext,
            starting_key,
            max_rounds
        )

        # Record the attempt number
        result["attempt"] = attempt + 1

        # Step 4: Keep the best result
        if (
            best_result is None
            or result["quadgram_score"] >
            best_result["quadgram_score"]
        ):

            best_result = result

        # Step 5: Stop early if the text already reads like English
        if best_result["quadgram_score"] >= good_enough:
            break

    # Return the best candidate
    return best_result
