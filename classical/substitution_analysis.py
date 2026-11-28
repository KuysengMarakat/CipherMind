
# Import the substitution decryption function
from classical.substitution import substitution_decrypt


# English letters ordered from most common to least common
ENGLISH_FREQUENCY_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# All English letters
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Clean the input text
def clean_text(text):

    if not isinstance(text, str):
        raise TypeError("Input must be text")

    letters = ""

    for char in text:

        if char.isascii() and char.isalpha():

            letters += char.upper()

    return letters


# Count how many times each letter appears
def count_letters(text):

    letters = clean_text(text)

    frequencies = {}

    # Start every letter with a count of zero
    for char in ALPHABET:

        frequencies[char] = 0

    # Count each letter
    for char in letters:

        frequencies[char] += 1

    return frequencies


# Estimate the substitution key
def estimate_substitution_key(ciphertext):

    # Count the ciphertext letters
    frequencies = count_letters(ciphertext)

    if sum(frequencies.values()) == 0:
        raise ValueError("Input contains no English letters")

    # Sort ciphertext letters by frequency
    cipher_order = sorted(
        ALPHABET,
        key=lambda char: frequencies[char],
        reverse=True
    )

    # Create an empty substitution key
    key = [""] * 26

    # Match common ciphertext letters with common English letters
    for index in range(26):

        plain_letter = ENGLISH_FREQUENCY_ORDER[index]

        cipher_letter = cipher_order[index]

        # Find the position of the plaintext letter
        position = ord(plain_letter) - ord("A")

        # Store its estimated ciphertext replacement
        key[position] = cipher_letter

    return "".join(key)


# Analyse substitution ciphertext
def analyze_substitution(ciphertext):

    # Estimate the substitution key
    key = estimate_substitution_key(ciphertext)

    # Decrypt using the estimated key
    plaintext = substitution_decrypt(
        ciphertext,
        key
    )

    # Return the analysis results
    return {

        "key": key,

        "plaintext": plaintext,

        "letter_frequencies": count_letters(ciphertext)

    }
