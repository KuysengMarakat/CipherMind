

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


# Store the result from one plugin
@dataclass
class CandidateResult:

    # Plugin information
    plugin_name: str
    confidence: float
    cost: int

    # Decoded output
    decoded_data: Optional[bytes] = None

    # Scoring information
    scores: Dict[str, Any] = field(default_factory=dict)

    # Explanation
    explanation: str = ""

    # Store an error if execution fails
    error: Optional[str] = None


@dataclass
class CaesarCandidate:
    """One Caesar-shift result used by the educational report renderer."""
    shift: int
    score: float
    plaintext: str


@dataclass
class AnalysisResult:
    """Summary model for the classical-analysis report renderer."""
    character_count: int
    letter_count: int
    index_of_coincidence: float
    top_letters: list = field(default_factory=list)
    candidates: list = field(default_factory=list)

    def to_dict(self):
        return {
            "character_count": self.character_count,
            "letter_count": self.letter_count,
            "index_of_coincidence": self.index_of_coincidence,
            "top_letters": self.top_letters,
            "candidates": [
                {
                    "shift": item.shift,
                    "score": item.score,
                    "plaintext": item.plaintext,
                }
                for item in self.candidates
            ],
        }
