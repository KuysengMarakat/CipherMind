import re

from scoring.scorer import analyze_candidate


# ==========================================
# PLAINTEXT DETECTION CONFIGURATION
# ==========================================

MIN_ENGLISH_LETTERS = 8
MIN_WORD_COUNT = 2

MIN_PRINTABLE_RATIO = 0.95
MIN_WORD_SCORE = 0.60
MIN_QUALITY_SCORE = 0.75
MIN_QUADGRAM_SCORE = -7.0


# ==========================================
# DETECT ORIGINAL ENGLISH PLAINTEXT
# ==========================================

def is_likely_english_plaintext(data, scores=None):
    """
    Determine whether input is likely readable
    English plaintext.

    This is a heuristic classification system,
    not cryptographic proof.
    """

    # STEP 1: Validate input type.

    if not isinstance(data, bytes):
        raise TypeError("Input must be bytes")

    # STEP 2: Validate UTF-8.

    try:
        text = data.decode("utf-8")

    except UnicodeDecodeError:
        return False

    # STEP 3: Reject empty input.

    if not text.strip():
        return False

    # STEP 4: Extract English words.

    words = re.findall(r"[A-Za-z]+", text)

    if not words:
        return False

    # STEP 5: Count English letters.

    letter_count = sum(
        len(word) for word in words
    )

    # Reject ambiguous short input.

    if letter_count < MIN_ENGLISH_LETTERS:
        return False

    if len(words) < MIN_WORD_COUNT:
        return False

    # STEP 6: Calculate scoring measurements.

    if scores is None:

        scores = analyze_candidate(
            data,
            data
        )

    # STEP 7: Extract measurements.

    printable = scores.get(
        "printable_ratio", 0.0
    )

    word = scores.get(
        "word_score", 0.0
    )

    quality = scores.get(
        "quality_score", 0.0
    )

    quadgram = scores.get(
        "quadgram_score"
    )

    # STEP 8: Reject unavailable quadgram analysis.

    if quadgram is None:
        return False

    # STEP 9: Evaluate English characteristics.

    return (
        printable >= MIN_PRINTABLE_RATIO
        and word >= MIN_WORD_SCORE
        and quality >= MIN_QUALITY_SCORE
        and quadgram >= MIN_QUADGRAM_SCORE
    )
