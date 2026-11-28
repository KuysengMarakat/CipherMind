"""Digest calculation and password-hash verification/auditing.

MD5 and SHA-1 are included for compatibility and identification only. Do not
use them for new password storage or security-sensitive integrity designs.
Use Argon2id or bcrypt for password storage.
"""
import hashlib


_DIGESTS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "sha224": hashlib.sha224,
    "sha384": hashlib.sha384,
}


def calculate_digest(data, algorithm="sha256"):
    """Return a hexadecimal digest for bytes or UTF-8 text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, bytes):
        raise TypeError("Digest input must be bytes or text")
    try:
        constructor = _DIGESTS[algorithm.lower()]
    except (AttributeError, KeyError):
        raise ValueError("Supported digests: " + ", ".join(sorted(_DIGESTS)))
    return constructor(data).hexdigest()


def hash_password_bcrypt(password, rounds=12):
    """Create a bcrypt password hash. Requires the bcrypt package."""
    if not isinstance(password, str):
        raise TypeError("Password must be text")
    if not 4 <= rounds <= 16:
        raise ValueError("bcrypt rounds must be between 4 and 16")
    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError("Install bcrypt with: python3 -m pip install bcrypt") from exc
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=rounds),
    ).decode("ascii")


def verify_password_bcrypt(password, encoded_hash):
    """Verify a bcrypt password hash. Returns False for a non-matching password."""
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        raise TypeError("Password and encoded hash must be text")
    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError("Install bcrypt with: python3 -m pip install bcrypt") from exc
    try:
        return bcrypt.checkpw(password.encode("utf-8"), encoded_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def hash_password_argon2(password, time_cost=3, memory_cost=65536, parallelism=4):
    """Create an Argon2id password hash using argon2-cffi."""
    if not isinstance(password, str):
        raise TypeError("Password must be text")
    try:
        from argon2 import PasswordHasher
    except ImportError as exc:
        raise RuntimeError("Install argon2-cffi with: python3 -m pip install argon2-cffi") from exc
    if time_cost < 1 or memory_cost < 8 or parallelism < 1:
        raise ValueError("Argon2 costs must be positive and memory_cost at least 8 KiB")
    return PasswordHasher(
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
    ).hash(password)


def verify_password_argon2(password, encoded_hash):
    """Verify an Argon2 encoded hash; return False for a mismatch or invalid hash."""
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        raise TypeError("Password and encoded hash must be text")
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerificationError, InvalidHashError
    except ImportError as exc:
        raise RuntimeError("Install argon2-cffi with: python3 -m pip install argon2-cffi") from exc
    try:
        return PasswordHasher().verify(encoded_hash, password)
    except (VerificationError, InvalidHashError, ValueError):
        return False


def verify_password_hash(password, encoded_hash):
    """Identify and verify bcrypt or Argon2 password hashes."""
    from modern.hash_identifier import identify_hash
    formats = identify_hash(encoded_hash)
    if "bcrypt" in formats:
        return verify_password_bcrypt(password, encoded_hash)
    if any(item.startswith("Argon2") for item in formats):
        return verify_password_argon2(password, encoded_hash)
    raise ValueError("Only bcrypt and Argon2 encoded password hashes can be verified here")


def audit_password_hash(encoded_hash, wordlist_path, max_candidates=100000):
    """Try a bounded local wordlist against a bcrypt or Argon2 hash.

    Use only hashes you own or are explicitly authorized to audit. The wordlist
    is streamed rather than loaded into memory. The first matching entry is
    returned, along with the number of attempts.
    """
    if not isinstance(wordlist_path, str):
        raise TypeError("wordlist_path must be text")
    if not isinstance(max_candidates, int) or max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    from modern.hash_identifier import identify_hash
    formats = identify_hash(encoded_hash)
    if "bcrypt" not in formats and not any(x.startswith("Argon2") for x in formats):
        raise ValueError("Wordlist auditing supports bcrypt and Argon2 hashes only")
    tested = 0
    with open(wordlist_path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if tested >= max_candidates:
                break
            candidate = line.rstrip("\r\n")
            tested += 1
            if verify_password_hash(candidate, encoded_hash):
                return {
                    "matched": True,
                    "candidate": candidate,
                    "tested": tested,
                    "algorithm": formats[0],
                }
    return {
        "matched": False,
        "candidate": None,
        "tested": tested,
        "algorithm": formats[0],
    }
