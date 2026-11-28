"""
Result status labels for CipherMind (proposal Section 3.5).

VERIFIED            A hard check passed (a flag pattern matched) and
                    re-running the whole chain from the original input
                    reproduces the same output.
PARTIALLY VERIFIED  The output reads like English, but no hard check
                    confirms it.
UNSOLVED            Neither of the above. The best leads are still shown.
"""

from scoring.plaintext_detection import is_likely_english_plaintext

VERIFIED = "VERIFIED"
PARTIALLY_VERIFIED = "PARTIALLY VERIFIED"
UNSOLVED = "UNSOLVED"

STATUS_MEANING = {
    VERIFIED: "flag pattern matched and the chain was re-run successfully",
    PARTIALLY_VERIFIED: "reads like English, but no flag or other hard check confirms it",
    UNSOLVED: "no convincing result within the search limits",
}


def get_status(data, scores, flag_matched, chain_reproduced=True):
    """Return VERIFIED, PARTIALLY VERIFIED or UNSOLVED for one result."""

    if flag_matched and chain_reproduced:
        return VERIFIED

    if isinstance(data, bytes) and is_likely_english_plaintext(data, scores):
        return PARTIALLY_VERIFIED

    return UNSOLVED
