"""Caesar cipher transform, intended for learning and puzzle text only."""

import string


def decrypt_caesar(text: str, shift: int) -> str:
    """Shift ASCII letters backward; preserve case, punctuation, and spacing."""
    shift %= 26
    output: list[str] = []
    for char in text:
        if char in string.ascii_lowercase:
            output.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))
        elif char in string.ascii_uppercase:
            output.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
        else:
            output.append(char)
    return "".join(output)
