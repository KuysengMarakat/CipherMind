"""A transparent character-frequency score for English-like plaintext."""

from collections import Counter
import string

_EXPECTED = {
    "a": .0817, "b": .0149, "c": .0278, "d": .0425, "e": .1270,
    "f": .0223, "g": .0202, "h": .0609, "i": .0697, "j": .0015,
    "k": .0077, "l": .0403, "m": .0241, "n": .0675, "o": .0751,
    "p": .0193, "q": .0010, "r": .0599, "s": .0633, "t": .0906,
    "u": .0276, "v": .0098, "w": .0236, "x": .0015, "y": .0197,
    "z": .0007,
}


def english_score(text: str) -> float:
    """Return a higher-is-more-English chi-squared score."""
    letters = [char.lower() for char in text if char in string.ascii_letters]
    if not letters:
        return float("-inf")
    counts = Counter(letters)
    length = len(letters)
    chi_squared = sum(
        (counts.get(letter, 0) - length * expected) ** 2 / (length * expected)
        for letter, expected in _EXPECTED.items()
    )
    return -chi_squared
