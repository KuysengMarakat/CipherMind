
from scoring.printable_score import calculate_printable_ratio

from scoring.quadgram_score import (
    load_quadgram_scores,
    calculate_quadgram_score
)

from scoring.entropy_score import (
    calculate_entropy,
    calculate_entropy_change
)


# Load English dataset once
QUADGRAM_SCORES, FLOOR_SCORE = load_quadgram_scores(
    "data/english_quadgrams.txt"
)


# Analyse one decoded candidate

def analyze_candidate(parent_data, candidate_data):

    # Calculate printable ratio
    printable_ratio = calculate_printable_ratio(candidate_data)


    # Calculate English quadgram score
    quadgram_score = calculate_quadgram_score(
        candidate_data,
        QUADGRAM_SCORES,
        FLOOR_SCORE
    )


    # Calculate entropy before transformation
    parent_entropy = calculate_entropy(parent_data)


    # Calculate entropy after transformation
    candidate_entropy = calculate_entropy(candidate_data)


    # Calculate entropy change
    entropy_change = calculate_entropy_change(
        parent_data,
        candidate_data
    )


    # Collect all results
    results = {

        "printable_ratio": printable_ratio,

        "quadgram_score": quadgram_score,

        "parent_entropy": parent_entropy,

        "candidate_entropy": candidate_entropy,

        "entropy_change": entropy_change

    }


    return results
