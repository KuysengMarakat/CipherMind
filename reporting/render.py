"""Render analysis results as readable text or JSON."""

import json

from core.models import AnalysisResult


def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.to_dict(), indent=2, ensure_ascii=False)


def render_markdown(result: AnalysisResult) -> str:
    lines = [
        "CipherMind — Classical Cipher Analysis",
        "=" * 40,
        f"Characters: {result.character_count}",
        f"Latin letters: {result.letter_count}",
        f"Index of coincidence: {result.index_of_coincidence:.4f}",
        "",
        "Most frequent letters:",
    ]
    lines.extend(f"  {letter}: {count}" for letter, count in result.top_letters)
    lines.extend(("", "Top Caesar-shift candidates:"))
    lines.extend(
        f"  shift {item.shift:2d} (score {item.score:.2f}): {item.plaintext}"
        for item in result.candidates
    )
    lines.extend(("", "Educational note: Caesar analysis applies only to this classical toy cipher."))
    return "\n".join(lines)
