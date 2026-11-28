
# Convert a letter into a number
def letter_to_number(char):

    return ord(char.upper()) - ord("A")


# Convert a number into a letter
def number_to_letter(number, uppercase=True):

    letter = chr(number + ord("A"))

    if uppercase:
        return letter

    return letter.lower()


# Check whether the keyword is valid
def validate_key(key):

    if not isinstance(key, str):
        raise TypeError("Key must be text")

    if not key or not key.isascii() or not key.isalpha():
        raise ValueError("Key must contain English letters only")

    return key.upper()


# Perform Vigenere transformation
def vigenere_transform(text, key, decrypt=False):

    if not isinstance(text, str):
        raise TypeError("Input must be text")

    key = validate_key(key)

    result = []

    key_index = 0

    # Process each character
    for char in text:

        # Handle uppercase and lowercase English letters
        if char.isascii() and char.isalpha():

            # Get the text letter number
            text_number = letter_to_number(char)

            # Get the corresponding key letter
            key_number = letter_to_number(
                key[key_index % len(key)]
            )

            # Encrypt or decrypt
            if decrypt:
                new_number = (
                    text_number - key_number
                ) % 26

            else:
                new_number = (
                    text_number + key_number
                ) % 26

            # Keep the original letter case
            new_char = number_to_letter(
                new_number,
                char.isupper()
            )

            result.append(new_char)

            # Move to the next key letter
            key_index += 1

        else:

            # Preserve spaces, numbers and symbols
            result.append(char)

    return "".join(result)


# Encrypt a message
def vigenere_encrypt(text, key):

    return vigenere_transform(text, key)


# Decrypt a message
def vigenere_decrypt(text, key):

    return vigenere_transform(
        text,
        key,
        decrypt=True
    )
