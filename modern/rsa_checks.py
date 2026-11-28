"""Small RSA weakness checks for CTF challenge parameters.

These functions do not attack a remote system. They analyze numbers supplied
by the user and only perform bounded, educational checks.
"""
from math import gcd, isqrt


def integer_nth_root(value, exponent):
    """Return floor(value ** (1/exponent)) using integer arithmetic."""
    if not isinstance(value, int) or value < 0:
        raise ValueError("value must be a non-negative integer")
    if not isinstance(exponent, int) or exponent < 1:
        raise ValueError("exponent must be a positive integer")
    if value < 2 or exponent == 1:
        return value
    low, high = 0, 1
    while high ** exponent <= value:
        high *= 2
    while low + 1 < high:
        middle = (low + high) // 2
        if middle ** exponent <= value:
            low = middle
        else:
            high = middle
    return low


def small_exponent_root(ciphertext, exponent):
    """Recover m only when ciphertext is exactly m**e (no modular wrap)."""
    root = integer_nth_root(ciphertext, exponent)
    if root ** exponent == ciphertext:
        return root
    return None


def fermat_factor(n, max_steps=100_000):
    """Try Fermat factorisation for n with two close odd factors."""
    if not isinstance(n, int) or n < 9 or n % 2 == 0:
        raise ValueError("n must be an odd integer greater than 2")
    if not isinstance(max_steps, int) or max_steps < 1:
        raise ValueError("max_steps must be positive")
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_steps):
        difference = a * a - n
        b = isqrt(difference)
        if b * b == difference:
            p, q = a - b, a + b
            if p > 1 and q > 1 and p * q == n:
                return p, q
        a += 1
    return None


def shared_factor(modulus_a, modulus_b):
    """Return a shared non-trivial factor if two RSA moduli share one."""
    if not all(isinstance(value, int) and value > 1 for value in (modulus_a, modulus_b)):
        raise ValueError("RSA moduli must be integers greater than 1")
    factor = gcd(modulus_a, modulus_b)
    if factor in (1, modulus_a, modulus_b):
        return None
    return factor
