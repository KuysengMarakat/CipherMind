
# Affine Cipher constants

ALPHABET_SIZE = 26

# These numbers have a modular inverse modulo 26
VALID_A_VALUES = [
    1, 3, 5, 7, 9, 11,
    15, 17, 19, 21, 23, 25
]


# Find the modular inverse of a number
def modular_inverse(a, modulus):

    for number in range(modulus):

        if (a * number) % modulus == 1:

            return number

    raise ValueError("No modular inverse exists")


# Decrypt Affine Cipher
def affine_decrypt(text, a, b):

    if not isinstance(text, str):
        raise TypeError("Input must be text")

    if a not in VALID_A_VALUES:
        raise ValueError("Invalid multiplication key")

    if not 0 <= b < ALPHABET_SIZE:
        raise ValueError("Invalid addition key")

    # Find the inverse of a
    inverse_a = modular_inverse(a, ALPHABET_SIZE)

    result = []

    # Process each character
    for char in text:

        # Handle uppercase letters
        if "A" <= char <= "Z":

            position = ord(char) - ord("A")

            new_position = (
                inverse_a * (position - b)
            ) % ALPHABET_SIZE

            result.append(chr(new_position + ord("A")))

        # Handle lowercase letters
        elif "a" <= char <= "z":

            position = ord(char) - ord("a")

            new_position = (
                inverse_a * (position - b)
            ) % ALPHABET_SIZE

            result.append(chr(new_position + ord("a")))

        # Preserve spaces, numbers and symbols
        else:

            result.append(char)

    return "".join(result)
