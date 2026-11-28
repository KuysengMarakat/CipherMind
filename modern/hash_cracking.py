"""Bounded, local dictionary auditing for common password digests.

This module is intended for CTF exercises and hashes the user owns or is
explicitly authorized to audit. It does not reverse a hash mathematically; it
hashes candidate passwords and compares the results.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import struct
from typing import Iterable, Optional

from modern.hash_identifier import identify_hash


# Small, predictable first-pass list. The bundled English dictionary is tried
# after these candidates for fast, unsalted digests.
COMMON_CANDIDATES = (
    "123456", "password", "123456789", "12345678", "qwerty",
    "12345", "1234567", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "login",
    "abc123", "password1", "iloveyou", "hello", "world",
    "test", "secret", "guest", "root", "changeme",
    "computer", "security", "cryptography", "student", "hello123",
)

# A small, deterministic mutation set catches common CTF/password patterns
# without turning the default audit into an unbounded brute-force operation.
COMMON_SUFFIXES = (
    "!", "@", "#", "$", "1", "12", "123", "123!", "@123",
)

RAW_HASH_FUNCTIONS = {
    "MD5": lambda candidate: hashlib.md5(candidate.encode("utf-8")).hexdigest(),
    "SHA-1": lambda candidate: hashlib.sha1(candidate.encode("utf-8")).hexdigest(),
    "SHA-224": lambda candidate: hashlib.sha224(candidate.encode("utf-8")).hexdigest(),
    "SHA-256": lambda candidate: hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
    "SHA-384": lambda candidate: hashlib.sha384(candidate.encode("utf-8")).hexdigest(),
    "SHA-512": lambda candidate: hashlib.sha512(candidate.encode("utf-8")).hexdigest(),
    "NTLM": lambda candidate: md4(candidate.encode("utf-16le")).hex(),
}


def _rotate_left(value: int, count: int) -> int:
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF


def md4(message: bytes) -> bytes:
    """Return the MD4 digest (needed for NTLM hash verification).

    MD4 is implemented here only for compatibility with legacy NTLM hashes.
    It must not be used for new security designs.
    """
    if not isinstance(message, bytes):
        raise TypeError("MD4 input must be bytes")

    original_bit_length = (len(message) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = bytearray(message)
    padded.append(0x80)
    while len(padded) % 64 != 56:
        padded.append(0)
    padded.extend(struct.pack("<Q", original_bit_length))

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for offset in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[offset:offset + 64])
        a, b, c, d = a0, b0, c0, d0

        # Round 1: F(x,y,z) = (x & y) | (~x & z)
        shifts = (3, 7, 11, 19)
        for i in range(16):
            if i % 4 == 0:
                a = _rotate_left(a + ((b & c) | (~b & d)) + x[i], shifts[i % 4])
            elif i % 4 == 1:
                d = _rotate_left(d + ((a & b) | (~a & c)) + x[i], shifts[i % 4])
            elif i % 4 == 2:
                c = _rotate_left(c + ((d & a) | (~d & b)) + x[i], shifts[i % 4])
            else:
                b = _rotate_left(b + ((c & d) | (~c & a)) + x[i], shifts[i % 4])

        # Round 2: G(x,y,z) = (x & y) | (x & z) | (y & z)
        order = (0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15)
        shifts = (3, 5, 9, 13)
        for i, k in enumerate(order):
            if i % 4 == 0:
                a = _rotate_left(a + ((b & c) | (b & d) | (c & d)) + x[k] + 0x5A827999, shifts[i % 4])
            elif i % 4 == 1:
                d = _rotate_left(d + ((a & b) | (a & c) | (b & c)) + x[k] + 0x5A827999, shifts[i % 4])
            elif i % 4 == 2:
                c = _rotate_left(c + ((d & a) | (d & b) | (a & b)) + x[k] + 0x5A827999, shifts[i % 4])
            else:
                b = _rotate_left(b + ((c & d) | (c & a) | (d & a)) + x[k] + 0x5A827999, shifts[i % 4])

        # Round 3: H(x,y,z) = x ^ y ^ z
        order = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)
        shifts = (3, 9, 11, 15)
        for i, k in enumerate(order):
            if i % 4 == 0:
                a = _rotate_left(a + (b ^ c ^ d) + x[k] + 0x6ED9EBA1, shifts[i % 4])
            elif i % 4 == 1:
                d = _rotate_left(d + (a ^ b ^ c) + x[k] + 0x6ED9EBA1, shifts[i % 4])
            elif i % 4 == 2:
                c = _rotate_left(c + (d ^ a ^ b) + x[k] + 0x6ED9EBA1, shifts[i % 4])
            else:
                b = _rotate_left(b + (c ^ d ^ a) + x[k] + 0x6ED9EBA1, shifts[i % 4])

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def _candidate_sources(wordlist_path: Optional[str] = None, include_dictionary: bool = True):
    """Yield unique candidates from a supplied list, common list and dictionary."""
    seen = set()
    configured = wordlist_path or os.environ.get("CIPHERMIND_WORDLIST")

    # A user-supplied list takes priority. This is especially important for
    # slow password hashes, where the candidate budget is intentionally small.
    if configured:
        path = Path(configured).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"Wordlist does not exist: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                candidate = line.rstrip("\r\n")
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    yield candidate, str(path)

    for candidate in COMMON_CANDIDATES:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate, "built-in common candidates"

    # Try common capitalization and suffix mutations before scanning the
    # larger bundled dictionary. This catches patterns such as "hello@"
    # while keeping the default 50,000-candidate budget useful.
    for base in COMMON_CANDIDATES:
        for candidate in (base.capitalize(), base.upper()):
            if candidate not in seen:
                seen.add(candidate)
                yield candidate, "built-in common mutations"

        for suffix in COMMON_SUFFIXES:
            for candidate in (base + suffix, base.capitalize() + suffix):
                if candidate not in seen:
                    seen.add(candidate)
                    yield candidate, "built-in common mutations"

    if include_dictionary:
        dictionary = Path(__file__).resolve().parent.parent / "data" / "english_words.txt"
        if dictionary.is_file():
            with dictionary.open("r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    candidate = line.rstrip("\r\n")
                    if candidate and candidate not in seen:
                        seen.add(candidate)
                        yield candidate, "bundled English dictionary"


def crack_raw_digest(
    digest: str,
    wordlist_path: Optional[str] = None,
    max_candidates: int = 50000,
) -> dict:
    """Try a bounded dictionary against an unsalted raw digest.

    Supports MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512.
    A match is a candidate recovery, not proof of the original plaintext when
    the format itself is ambiguous (for example, MD5 versus NTLM).
    """
    if not isinstance(digest, str):
        raise TypeError("Digest must be text")
    digest = digest.strip().lower()
    formats = identify_hash(digest)
    algorithms = [name for name in formats if name in RAW_HASH_FUNCTIONS]
    if not algorithms:
        raise ValueError("Input is not a supported raw hexadecimal digest")
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise ValueError("max_candidates must be a positive integer")

    tested = 0
    for candidate, source in _candidate_sources(wordlist_path, include_dictionary=True):
        if tested >= max_candidates:
            break
        tested += 1
        for algorithm in algorithms:
            if RAW_HASH_FUNCTIONS[algorithm](candidate).lower() == digest:
                return {
                    "matched": True,
                    "candidate": candidate,
                    "algorithm": algorithm,
                    "possible_algorithms": formats,
                    "tested": tested,
                    "source": source,
                    "limit_reached": False,
                }

    return {
        "matched": False,
        "candidate": None,
        "algorithm": None,
        "possible_algorithms": formats,
        "tested": tested,
        "source": "configured and bundled wordlists",
        "limit_reached": tested >= max_candidates,
    }


def audit_encoded_password_hash(
    encoded_hash: str,
    wordlist_path: Optional[str] = None,
    max_candidates: int = 25,
) -> dict:
    """Try a small bounded candidate list against bcrypt/Argon2 hashes.

    Slow password hashes are deliberately limited to a small default number
    of candidates. A user-supplied wordlist may be provided explicitly.
    """
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise ValueError("max_candidates must be a positive integer")

    from modern.hashing import verify_password_hash

    formats = identify_hash(encoded_hash)
    tested = 0
    try:
        for candidate, source in _candidate_sources(wordlist_path, include_dictionary=False):
            if tested >= max_candidates:
                break
            tested += 1
            if verify_password_hash(candidate, encoded_hash):
                return {
                    "matched": True,
                    "candidate": candidate,
                    "algorithm": formats[0] if formats else "unknown",
                    "possible_algorithms": formats,
                    "tested": tested,
                    "source": source,
                    "limit_reached": False,
                }
    except RuntimeError as error:
        return {
            "matched": False,
            "candidate": None,
            "algorithm": formats[0] if formats else "unknown",
            "possible_algorithms": formats,
            "tested": tested,
            "source": "dependency unavailable",
            "error": str(error),
            "limit_reached": False,
        }

    return {
        "matched": False,
        "candidate": None,
        "algorithm": formats[0] if formats else "unknown",
        "possible_algorithms": formats,
        "tested": tested,
        "source": "built-in common candidates",
        "limit_reached": tested >= max_candidates,
    }
