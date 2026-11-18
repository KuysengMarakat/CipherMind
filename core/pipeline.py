"""Orchestration for educational classical-cipher analysis."""

from core.models import AnalysisResult, Candidate
from intelligence.frequency import frequency_summary, index_of_coincidence
from plugins.caesar import decrypt_caesar
from scoring.english import english_score
from validation.input import validate_top_n


def analyze_caesar(text: str, top_n: int = 5) -> AnalysisResult:
    """Rank all Caesar shifts for *text* using a simple English score."""
    validate_top_n(top_n)
    letters, top_letters = frequency_summary(text)
    candidates = []
    for shift in range(26):
        plaintext = decrypt_caesar(text, shift)
        candidates.append(Candidate(shift=shift, plaintext=plaintext, score=english_score(plaintext)))
    candidates.sort(key=lambda candidate: candidate.score, reverse=True)
    return AnalysisResult(
        character_count=len(text),
        letter_count=len(letters),
        index_of_coincidence=index_of_coincidence(letters),
        top_letters=top_letters,
        candidates=candidates[:top_n],
    )
