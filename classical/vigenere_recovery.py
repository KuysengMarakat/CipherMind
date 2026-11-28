
# Import existing Vigenere functions
from classical.vigenere import vigenere_decrypt

from classical.vigenere_analysis import get_letters

from scoring.scorer import QUADGRAM_SCORES, FLOOR_SCORE

from scoring.quadgram_score import calculate_quadgram_score


# English letter frequency percentages
ENGLISH_FREQUENCIES = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
    0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
    0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974,
    0.00074
]


# Find the most likely Caesar shift
def find_best_shift(text):

    counts = [0] * 26

    # Count each letter
    for char in text:

        position = ord(char) - ord("A")

        counts[position] += 1

    total = len(text)

    best_shift = 0

    best_score = float("inf")

    # Try all 26 possible shifts
    for shift in range(26):

        score = 0

        for position in range(26):

            # Expected English frequency
            expected = ENGLISH_FREQUENCIES[position] * total

            # Find the corresponding ciphertext letter
            cipher_position = (position + shift) % 26

            observed = counts[cipher_position]

            # Calculate chi-square score
            score += (
                (observed - expected) ** 2
            ) / expected

        # Smaller score means a better match
        if score < best_score:

            best_score = score

            best_shift = shift

    return best_shift


def english_fitness(text):
    """Average quadgram score of text (higher means more English-like)."""
    score = calculate_quadgram_score(
        text.encode("utf-8"),
        QUADGRAM_SCORES,
        FLOOR_SCORE
    )
    if score is None:
        return float("-inf")
    return score


def refine_vigenere_key(ciphertext, key, rounds=2):
    """
    Improve a Vigenere key by hill climbing.

    For each key position, try all 26 letters and keep the one that
    makes the whole decryption most English-like. Repeat for a few
    rounds, because changing one letter can help another.

    Only the first 400 characters are used for scoring. That is
    enough to judge English and keeps long texts fast. The key stays
    aligned because the sample starts at the beginning of the text.
    """
    ciphertext = ciphertext[:400]
    key = list(key)
    best_score = english_fitness(vigenere_decrypt(ciphertext, "".join(key)))

    for _ in range(rounds):
        improved = False
        for position in range(len(key)):
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                trial = key.copy()
                trial[position] = letter
                score = english_fitness(
                    vigenere_decrypt(ciphertext, "".join(trial))
                )
                if score > best_score:
                    best_score = score
                    key = trial
                    improved = True
        if not improved:
            break

    return "".join(key)


def shortest_repeating_key(key):
    """Return the shortest key that repeats to form key (LEMONLEMON -> LEMON)."""
    for length in range(1, len(key) + 1):
        if len(key) % length == 0:
            if key[:length] * (len(key) // length) == key:
                return key[:length]
    return key


# Recover a possible Vigenere key
def recover_vigenere_key(ciphertext, key_length):

    # Check input
    if not isinstance(ciphertext, str):

        raise TypeError("Input must be text")

    if not isinstance(key_length, int) or isinstance(key_length, bool):

        raise TypeError("Key length must be an integer")

    if key_length < 1:

        raise ValueError("Key length must be positive")

    # Extract English letters
    letters = get_letters(ciphertext)

    if not letters:

        raise ValueError("No English letters found")

    if key_length > len(letters):

        raise ValueError("Key length is too large")

    # Store recovered key letters
    key = []

    # Analyse each key position
    for position in range(key_length):

        # Extract letters belonging to this position
        column = letters[position::key_length]

        # Find the most likely shift
        shift = find_best_shift(column)

        # Convert shift into a key letter
        key_letter = chr(shift + ord("A"))

        key.append(key_letter)

    # Combine key letters
    recovered_key = "".join(key)

    # Frequency analysis is unreliable on short columns, so improve
    # the key with quadgram hill climbing, then remove repetition
    # (for example "LEMONLEMON" becomes "LEMON").
    recovered_key = refine_vigenere_key(ciphertext, recovered_key)
    recovered_key = shortest_repeating_key(recovered_key)

    # Decrypt using the recovered key
    plaintext = vigenere_decrypt(
        ciphertext,
        recovered_key
    )

    # Return both key and plaintext
    return {

        "key": recovered_key,

        "plaintext": plaintext

    }
