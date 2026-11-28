# CipherMind Expanded Build

This build extends the uploaded CipherMind source while preserving the existing
encoding, classical-cipher, XOR, scoring, ranking, search and interactive CLI
workflows.

## Changes in this build

- Added AES-GCM authenticated encryption/decryption and key generation.
- Added RSA key generation, OAEP encryption/decryption, and PSS signatures.
- Added DES/3DES CBC compatibility helpers for legacy educational use only.
- Added finite-field Diffie–Hellman key agreement and HKDF derivation.
- Added elliptic-curve ECDH, ECDSA and HKDF derivation.
- Extended hash-format hints to bcrypt and Argon2 formats.
- Added MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 digest calculation.
- Added bcrypt and Argon2 password hashing and verification.
- Added bounded local wordlist auditing for authorized bcrypt/Argon2 hashes.
- Added `crypto` and `hash` command groups to `main.py`.
- Added automatic hash detection and bounded dictionary auditing to the normal interactive input prompt.
- Added raw MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 candidate verification.
- Added a built-in common-candidate list, capitalization variants and bounded suffix mutations (`!`, `@`, `#`, `$`, digits) before scanning the bundled English dictionary. This recovers common patterns such as `hello@` without unbounded brute force.
- Added NTLM candidate verification using an MD4 implementation for legacy compatibility.
- Added `--hash-wordlist`, `--hash-max-candidates` and `--slow-hash-max-candidates` controls.
- Added `--force-cryptanalysis` for ambiguous raw hexadecimal inputs that should be treated as encoded data.
- Updated README, architecture documentation and project report.
- Added automated tests for modern cryptography and hashing.

## Verification in the build environment

- `python3 -m compileall -q .` completed successfully.
- `python3 -m unittest discover -s tests -v`: 115 tests passed; one bcrypt test
  was skipped because `bcrypt` was not installed in the build environment (116 total).
- Added regression coverage for SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 and
  automatic recovery of the SHA-256 digest for `hello@` through the normal prompt.
- Automatic MD5 dictionary recovery returned `hello` for the known MD5 test vector.
- Automatic SHA-256 dictionary/mutation recovery returned `hello@` after 316 candidate checks.
- NTLM dictionary recovery passed the standard `password` test vector.
- Automatic bcrypt and Argon2 routing/audit tests passed; bcrypt verification itself
  remains dependency-gated when bcrypt is not installed.
- Existing Caesar interactive analysis still returned `HELLO WORLD`.
- AES-GCM encryption/decryption CLI smoke test passed.
- RSA key generation, OAEP encryption/decryption CLI smoke test passed.
- Diffie–Hellman key agreement demonstration passed.
- ECC ECDH/ECDSA demonstration passed.
- Existing interactive Caesar pipeline smoke test passed.

Install all declared dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

## Security limitations

- Modern cryptographic operations require correct keys and parameters.
- Diffie–Hellman and ECDH establish shared secrets; they do not encrypt messages
  or authenticate peers by themselves.
- DES and 3DES are obsolete and included for legacy educational compatibility.
- MD5 and SHA-1 are legacy digest algorithms, not recommended for new security.
- Hash identification is heuristic. Hashes are not decrypted; candidates are
  hashed and compared.
- Wordlist auditing is bounded and must only be used on hashes the user owns or
  is authorized to audit. A failed audit only means no tested candidate matched.
- Candidate quality scores are heuristics, not proof of correctness.
