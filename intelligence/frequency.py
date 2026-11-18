"""Letter-frequency helpers for Latin-alphabet text."""

from collections import Counter
import string


def frequency_summary(text: str) -> tuple[str, list[tuple[str, int]]]:
    """Return normalized letters and the five most frequent letters."""
    letters = "".join(char.lower() for char in text if char in string.ascii_letters)
    return letters, Counter(letters).most_common(5)


def index_of_coincidence(letters: str) -> float:
    """Compute the index of coincidence for normalized letters."""
    size = len(letters)
    if size < 2:
        return 0.0
    counts = Counter(letters)
    return sum(count * (count - 1) for count in counts.values()) / (size * (size - 1))
