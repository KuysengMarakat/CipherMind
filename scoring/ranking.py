
# Rank decoded candidates
def rank_candidates(results):

    # Sort candidates from highest to lowest quality
    ranked = sorted(
        results,
        key=get_ranking_score,
        reverse=True
    )

    return ranked


# Calculate ranking values
def get_ranking_score(result):

    # Failed candidates go to the bottom
    if result.error:
        return (0, 0, 0, 0)

    scores = result.scores or {}

    # Get overall quality score
    quality = scores.get("quality_score", 0)

    # Get additional measurements
    quadgram = scores.get("quadgram_score")

    printable = scores.get("printable_ratio", 0)

    # Handle missing Quadgram score
    if quadgram is None:
        quadgram = float("-inf")

    # Return ranking values
    return (
        1,
        quality,
        quadgram,
        printable
    )
