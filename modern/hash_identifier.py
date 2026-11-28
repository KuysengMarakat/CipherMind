"""Heuristic identification of common digest and password-hash formats.

A format match is not proof of the algorithm: several algorithms share the
same digest length, and arbitrary hex strings can have the same length.
"""
import re

HASH_LENGTHS = {
    32: ["MD5", "NTLM"],
    40: ["SHA-1"],
    56: ["SHA-224"],
    64: ["SHA-256"],
    96: ["SHA-384"],
    128: ["SHA-512"],
}


def identify_hash(value):
    if not isinstance(value, str):
        raise TypeError("Hash input must be text")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError("Hash input cannot be empty")

    if re.match(r"^\$2[aby]\$\d{2}\$", cleaned):
        return ["bcrypt"]
    if cleaned.startswith("$argon2id$"):
        return ["Argon2id"]
    if cleaned.startswith("$argon2i$"):
        return ["Argon2i"]
    if cleaned.startswith("$argon2d$"):
        return ["Argon2d"]

    if any(char not in "0123456789abcdefABCDEF" for char in cleaned):
        return []
    return HASH_LENGTHS.get(len(cleaned), [])
