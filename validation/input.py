"""Validation for local text input and CLI options."""

from pathlib import Path

MAX_INPUT_BYTES = 1_000_000


class InputValidationError(ValueError):
    """Raised when text input falls outside the supported bounds."""


def validate_top_n(top_n: int) -> None:
    if not 1 <= top_n <= 26:
        raise ValueError("--top must be between 1 and 26")


def read_text(path: Path) -> str:
    """Read a bounded local UTF-8 file."""
    size = path.stat().st_size
    if size > MAX_INPUT_BYTES:
        raise InputValidationError(f"input exceeds the {MAX_INPUT_BYTES:,}-byte limit")
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise InputValidationError("input file is empty")
    return text
