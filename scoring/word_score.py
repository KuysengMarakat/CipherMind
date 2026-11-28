"""
CipherMind English Vocabulary Scoring.

Measures how many recognized English words appear
in a decoded candidate.
"""

import re
from pathlib import Path


# ==========================================
# 1. CONFIGURATION
# ==========================================

DATA_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "english_words.txt"
)

WORD_PATTERN = re.compile(
    r"[A-Za-z]+(?:'[A-Za-z]+)*"
)


# ==========================================
# 2. FALLBACK VOCABULARY
# ==========================================

FALLBACK_WORDS = {
    "A", "ABOUT", "AFTER", "AGAIN", "ALL",
    "ALSO", "AM", "AN", "AND", "ANY",
    "ARE", "AS", "AT", "BACK", "BE",
    "BECAUSE", "BEEN", "BEFORE", "BUT", "BY",
    "CAN", "COME", "COULD", "DAY", "DID",
    "DO", "DOWN", "EACH", "EVEN", "EVERY",
    "FIND", "FIRST", "FOR", "FROM", "GET",
    "GIVE", "GO", "GOOD", "HAD", "HAS",
    "HAVE", "HE", "HER", "HERE", "HIM",
    "HIS", "HOW", "I", "IF", "IN",
    "INTO", "IS", "IT", "ITS", "JUST",
    "KNOW", "LIKE", "LOOK", "MAKE", "MANY",
    "ME", "MORE", "MOST", "MY", "NEW",
    "NO", "NOT", "NOW", "OF", "ON",
    "ONE", "ONLY", "OR", "OUR", "OUT",
    "OVER", "PEOPLE", "SAY", "SEE", "SHE",
    "SO", "SOME", "TAKE", "THAN", "THAT",
    "THE", "THEM", "THEN", "THERE", "THEY",
    "THIS", "TIME", "TO", "TWO", "UP",
    "USE", "VERY", "WANT", "WAS", "WAY",
    "WE", "WELL", "WERE", "WHAT", "WHEN",
    "WHERE", "WHICH", "WHO", "WILL", "WITH",
    "WORK", "WOULD", "YOU", "YOUR",
    "HELLO", "WORLD", "ATTACK", "SECRET",
    "MESSAGE", "DAWN"
}


# ==========================================
# 3. LOAD ENGLISH VOCABULARY
# ==========================================

def load_english_words(file_path=DATA_FILE):

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            words = {
                line.strip().casefold()
                for line in file
                if line.strip()
                and not line.startswith("#")
            }

        if words:
            return words

    except OSError:
        pass

    # Use fallback vocabulary if dataset is missing.
    return {
        word.casefold()
        for word in FALLBACK_WORDS
    }


# Load dictionary once.
# Avoid repeatedly reading the file for every candidate.

COMMON_WORDS = load_english_words()


# ==========================================
# 4. CHECK ONE WORD
# ==========================================

# The dictionary file contains every single letter and many rare
# two-letter entries. Leftover pieces of leetspeak flags (for
# example "y", "e" and "s" in "y4l3e5") would then count as English.
# Very short words are therefore checked against small fixed lists.

ONE_LETTER_WORDS = {"a", "i"}

TWO_LETTER_WORDS = {
    "am", "an", "as", "at", "be", "by", "do", "go",
    "he", "hi", "if", "in", "is", "it", "me", "my",
    "no", "of", "oh", "ok", "on", "or", "so", "to",
    "up", "us", "we"
}


def is_english_word(word):
    """Return True if a lower-case word counts as real English."""

    if len(word) == 1:
        return word in ONE_LETTER_WORDS

    if len(word) == 2:
        return word in TWO_LETTER_WORDS

    return word in COMMON_WORDS


# ==========================================
# 5. CALCULATE ENGLISH WORD SCORE
# ==========================================

def calculate_word_score(data):

    # Validate input.
    if not isinstance(data, bytes):

        raise TypeError(
            "Input must be bytes"
        )

    # Decode UTF-8.
    try:

        text = data.decode("utf-8")

    except UnicodeDecodeError:

        return 0.0

    # Extract English words.
    words = WORD_PATTERN.findall(
        text.casefold()
    )

    # No recognizable words.
    if not words:

        return 0.0

    # Count recognized English words.
    matched_words = sum(
        is_english_word(word)
        for word in words
    )

    # Calculate normalized word score.
    score = matched_words / len(words)

    return max(
        0.0,
        min(1.0, score)
    )
