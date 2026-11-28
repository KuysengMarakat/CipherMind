"""Simple input and display-limit validation for CipherMind."""

MAX_INPUT_CHARS = 100_000


def validate_input(data, max_length=MAX_INPUT_CHARS):
    """Validate a text challenge before passing it to analysis plugins."""
    if not isinstance(data, str):
        raise TypeError("Input must be text")
    if not data.strip():
        raise ValueError("Input cannot be empty")
    if not isinstance(max_length, int) or max_length < 1:
        raise ValueError("Maximum input length must be positive")
    if len(data) > max_length:
        raise ValueError(f"Input is too long (maximum {max_length} characters)")
    return data


def validate_top_n(value, maximum=100):
    """Ensure a requested number of displayed results is reasonable."""
    if not isinstance(value, int):
        raise TypeError("Result count must be an integer")
    if value < 1 or value > maximum:
        raise ValueError(f"Result count must be between 1 and {maximum}")
    return value
