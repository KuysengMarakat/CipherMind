"""Shared result models used by CipherMind modules."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Candidate:
    """A possible Caesar shift, ranked by its English-likeness score."""

    shift: int
    plaintext: str
    score: float


@dataclass(frozen=True)
class AnalysisResult:
    """Analysis output for a single input string."""

    character_count: int
    letter_count: int
    index_of_coincidence: float
    top_letters: list[tuple[str, int]]
    candidates: list[Candidate]

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-ready representation."""
        return asdict(self)
