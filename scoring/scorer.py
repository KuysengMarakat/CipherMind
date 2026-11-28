
# ==========================================
# CIPHERMIND SCORING SYSTEM
# ==========================================

from pathlib import Path

# Import printable scoring
from scoring.printable_score import calculate_printable_ratio

# Import English quadgram scoring
from scoring.quadgram_score import (
    load_quadgram_scores,
    calculate_quadgram_score
)

# Import entropy analysis
from scoring.entropy_score import (
    calculate_entropy,
    calculate_entropy_change
)

# Import common English word scoring
from scoring.word_score import calculate_word_score


# ==========================================
# 1. LOAD ENGLISH QUADGRAM DATASET
# ==========================================

# Load English dataset once
DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "english_quadgrams.txt"
QUADGRAM_SCORES, FLOOR_SCORE = load_quadgram_scores(str(DATA_FILE))


# Calculate maximum score ONCE.
# Do not repeatedly scan the dictionary
# every time a candidate is evaluated.

BEST_QUADGRAM_SCORE = max(
    QUADGRAM_SCORES.values(),
    default=FLOOR_SCORE
)


# ==========================================
# 2. CALCULATE CANDIDATE QUALITY
# ==========================================

def calculate_quality_score(
    printable,
    word,
    quadgram
):

    # Give each measurement a weight
    total_score = printable * 0.20

    total_weight = 0.20

    # Common English word score
    total_score += word * 0.30

    total_weight += 0.30

    # Quadgram score
    if quadgram is not None and QUADGRAM_SCORES:

        # Use the precomputed maximum score
        best_score = BEST_QUADGRAM_SCORE

        score_range = best_score - FLOOR_SCORE

        if score_range > 0:

            quadgram_quality = (
                quadgram - FLOOR_SCORE
            ) / score_range

            # Keep the value between 0 and 1
            quadgram_quality = max(
                0.0,
                min(1.0, quadgram_quality)
            )

            total_score += quadgram_quality * 0.50

            total_weight += 0.50

    # Calculate final normalized quality
    return total_score / total_weight


# ==========================================
# 3. ANALYZE ONE DECODED CANDIDATE
# ==========================================

def analyze_candidate(
    parent_data,
    candidate_data
):

    # Calculate printable ratio
    printable_ratio = calculate_printable_ratio(
        candidate_data
    )

    # Calculate English word score
    word_score = calculate_word_score(
        candidate_data
    )

    # Calculate Quadgram score
    quadgram_score = calculate_quadgram_score(
        candidate_data,
        QUADGRAM_SCORES,
        FLOOR_SCORE
    )

    # Calculate original entropy
    parent_entropy = calculate_entropy(
        parent_data
    )

    # Calculate candidate entropy
    candidate_entropy = calculate_entropy(
        candidate_data
    )

    # Calculate entropy difference
    entropy_change = calculate_entropy_change(
        parent_data,
        candidate_data
    )

    # Calculate overall quality
    quality_score = calculate_quality_score(
        printable_ratio,
        word_score,
        quadgram_score
    )

    # Collect all analysis results
    return {

        "printable_ratio": printable_ratio,

        "word_score": word_score,

        "quadgram_score": quadgram_score,

        "quality_score": quality_score,

        "parent_entropy": parent_entropy,

        "candidate_entropy": candidate_entropy,

        "entropy_change": entropy_change

    }
