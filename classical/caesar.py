
# Caesar Cipher Decryption


def caesar_decrypt(text, shift):

    result = ""

    # Check every character
    for char in text:

        # Handle uppercase letters
        if "A" <= char <= "Z":

            position = ord(char) - ord("A")

            new_position = (position - shift) % 26

            new_char = chr(new_position + ord("A"))

            result += new_char


        # Handle lowercase letters
        elif "a" <= char <= "z":

            position = ord(char) - ord("a")

            new_position = (position - shift) % 26

            new_char = chr(new_position + ord("a"))

            result += new_char


        # Keep spaces and symbols unchanged
        else:

            result += char


    return result


# Try all possible Caesar shifts

def brute_force_caesar(text):

    candidates = []

    for shift in range(26):

        decoded = caesar_decrypt(text, shift)

        candidate = {

            "shift": shift,

            "result": decoded

        }

        candidates.append(candidate)


    return candidates
