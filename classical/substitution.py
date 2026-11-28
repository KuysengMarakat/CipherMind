
# English alphabet
ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# Check whether the substitution key is valid
def validate_key(key):

    if not isinstance(key, str):
        raise TypeError("Key must be text")

    key = key.upper()

    # The key must contain exactly 26 letters
    if len(key) != 26:
        raise ValueError("Key must contain 26 letters")

    # Only English letters are allowed
    if not all("A" <= char <= "Z" for char in key):
        raise ValueError("Key must contain English letters only")

    # Every letter must appear only once
    if len(set(key)) != 26:
        raise ValueError("Key cannot contain duplicate letters")

    return key


# Encrypt a message
def substitution_encrypt(text, key):

    key = validate_key(key)

    result = ""

    for char in text:

        # Check whether the character is an English letter
        if char.isascii() and char.isalpha():

            # Find the letter position
            position = ALPHABET.index(char.upper())

            # Replace it using the substitution key
            new_char = key[position]

            # Preserve uppercase and lowercase
            if char.islower():
                new_char = new_char.lower()

            result += new_char

        else:

            # Keep spaces and symbols unchanged
            result += char

    return result


# Decrypt a message
def substitution_decrypt(text, key):

    key = validate_key(key)

    result = ""

    for char in text:

        # Check whether the character is an English letter
        if char.isascii() and char.isalpha():

            # Find the character in the substitution key
            position = key.index(char.upper())

            # Recover the original alphabet letter
            new_char = ALPHABET[position]

            # Preserve uppercase and lowercase
            if char.islower():
                new_char = new_char.lower()

            result += new_char

        else:

            # Keep spaces and symbols unchanged
            result += char

    return result
