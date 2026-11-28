"""
Find RSA values in pasted challenge text and run the weakness checks.

CipherMind cannot break properly generated RSA. These checks only
succeed when a CTF challenge contains a deliberate weakness
(see modern/rsa_checks.py).
"""

import re

from modern.rsa_checks import (
    small_exponent_root,
    fermat_factor,
    shared_factor,
)

# Matches "n = 123", "e: 65537", "c1=0x1f" (numbered values allowed).
RSA_VALUE_PATTERN = re.compile(
    r"\b([nec])(\d*)\s*[=:]\s*(0x[0-9a-fA-F]+|\d+)",
    re.IGNORECASE,
)

SOLVED = "SOLVED"
NOT_APPLICABLE = "not applicable"


def parse_rsa_values(text):
    """
    Return a list of keys found in text, each as {"n": .., "e": .., "c": ..}.

    Values without a number (n, e, c) form key 1. Numbered values
    (n1, e1, c1, n2, ...) form one key per number. A shared e is
    copied to every key that has none.
    """
    groups = {}
    for name, number, value in RSA_VALUE_PATTERN.findall(text):
        key_number = number or "1"
        groups.setdefault(key_number, {})[name.lower()] = int(value, 0)

    shared_e = groups.get("1", {}).get("e")
    keys = []
    for number in sorted(groups, key=int):
        values = groups[number]
        if "e" not in values and shared_e is not None:
            values["e"] = shared_e
        if {"n", "e", "c"} <= set(values):
            keys.append(values)
    return keys


def looks_like_rsa(text):
    """True if the text contains at least one complete set of n, e and c."""
    return bool(parse_rsa_values(text))


def int_to_bytes(number):
    """Convert a recovered integer message back into bytes."""
    return number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")


def decrypt_with_factors(key, p, q):
    """Decrypt c when the two primes of n are known."""
    phi = (p - 1) * (q - 1)
    d = pow(key["e"], -1, phi)
    return pow(key["c"], d, key["n"])


def check_small_exponent(key):
    message = small_exponent_root(key["c"], key["e"])
    if message is None:
        return NOT_APPLICABLE, "c is not an exact e-th power", None
    return SOLVED, f"c is an exact e-th power (e = {key['e']}, so m^e < n)", message


def check_fermat(key, max_steps=20_000):
    if key["n"] % 2 == 0 or key["n"] < 9:
        return NOT_APPLICABLE, "n is too small or even", None
    factors = fermat_factor(key["n"], max_steps=max_steps)
    if factors is None:
        return NOT_APPLICABLE, "p and q are not close together", None
    p, q = factors
    return SOLVED, "p and q are close together", decrypt_with_factors(key, p, q)


def check_shared_factor(keys):
    """Try every pair of moduli. Returns one result per key."""
    results = []
    for index, key in enumerate(keys):
        found = None
        for other_index, other in enumerate(keys):
            if other_index != index and other["n"] != key["n"]:
                p = shared_factor(key["n"], other["n"])
                if p:
                    found = p
                    break
        if found is None:
            results.append((NOT_APPLICABLE, "no shared prime with another n", None))
        else:
            q = key["n"] // found
            message = decrypt_with_factors(key, found, q)
            results.append((SOLVED, f"n{index + 1} shares a prime with another n", message))
    return results


def solve_rsa(text):
    """
    Run every check on every key found in text.

    Returns a list of dicts: key number, check name, status, detail
    and recovered message bytes (or None).
    """
    keys = parse_rsa_values(text)
    report = []

    def add(number, check, outcome):
        status, detail, message = outcome

        # Proof: re-encrypting the recovered message must give c again.
        key = keys[number - 1]
        if message is not None and pow(message, key["e"], key["n"]) != key["c"]:
            status, detail, message = "failed", "re-encryption check failed", None
        elif message is not None:
            detail += "; re-encryption gives c again"

        report.append({
            "key": number,
            "check": check,
            "status": status,
            "detail": detail,
            "plaintext": int_to_bytes(message) if message is not None else None,
        })

    for number, key in enumerate(keys, start=1):
        add(number, "Small-exponent root", check_small_exponent(key))
        add(number, "Fermat factorisation", check_fermat(key))

    if len(keys) >= 2:
        for number, outcome in enumerate(check_shared_factor(keys), start=1):
            add(number, "Shared-factor GCD", outcome)

    return report
