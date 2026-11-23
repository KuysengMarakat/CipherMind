
def atbash_transform(text):

    result = ""

    for char in text:

        # Handle uppercase letters
        if "A" <= char <= "Z":

            position = ord(char) - ord("A")

            new_position = 25 - position

            new_char = chr(new_position + ord("A"))

            result += new_char


        # Handle lowercase letters
        elif "a" <= char <= "z":

            position = ord(char) - ord("a")

            new_position = 25 - position

            new_char = chr(new_position + ord("a"))

            result += new_char


        # Keep spaces and symbols unchanged
        else:

            result += char


    return result
