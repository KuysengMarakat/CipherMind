# CipherMind Fixed Release

## Changes in this release

- Preserves the automatic cryptanalysis pipeline, encoding plugins, classical cipher analysis, XOR analysis, scoring/ranking, and bounded multi-layer search.
- Preserves explicit AES-GCM, RSA, DES/3DES legacy, Diffie-Hellman, and ECC utilities.
- Preserves automatic raw-digest and bcrypt/Argon2 hash-format routing in the normal interactive prompt.
- Improves bounded raw-digest dictionary auditing with common capitalization and suffix mutations, including `hello@`.
- Adds regression tests for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and automatic SHA-256 recovery of `hello@`.

## Verification

- Python compilation: passed.
- Unit tests: 115 passed, 1 skipped (bcrypt package is not installed in the build environment).
- Normal CLI SHA-256 smoke test: detected SHA-256 and recovered `hello@` after 316 candidate checks.
- Normal CLI Caesar smoke test: recovered `HELLO WORLD` from `KHOOR ZRUOG`.
- Normal CLI Base32 smoke test: decoded `JBSWY3DP` to `Hello`.

## Notes

Hash identification is heuristic, and dictionary auditing is bounded. It tests candidate passwords; it does not reverse hashes. Use only on hashes you own or are authorized to audit. A failed dictionary audit does not prove a password is unrecoverable.

Install declared dependencies in a virtual environment with:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
