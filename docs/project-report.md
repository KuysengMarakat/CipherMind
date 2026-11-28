# CipherMind — Project Report

## Purpose

CipherMind is a local, educational cryptanalysis and cryptography toolkit. Its
automatic workflow analyzes unknown input, detects possible encodings, selects
suitable plugins, generates candidate transformations, executes them, scores
the outputs and ranks possible plaintexts.

It also provides explicit modern-cryptography and hash utilities for cases that
require keys, parameters or structured inputs.

## Implemented architecture

The automatic workflow consists of input intelligence, candidate generation,
a plugin registry, a core execution pipeline, scoring/ranking and reporting.
The project supports common encodings, classical ciphers, XOR analysis and
bounded multi-layer search.

The modern command path is separate from automatic candidate generation.
It supports AES-GCM, RSA-OAEP/RSA-PSS, legacy DES/3DES-CBC, finite-field
Diffie–Hellman, elliptic-curve ECDH/ECDSA, digest calculation, hash-format
hints, bcrypt and Argon2 password hashing/verification, and bounded local
wordlist auditing.

## Modern cryptography design

- **AES:** AES-GCM provides authenticated encryption and decryption. The API
  returns the nonce, ciphertext and authentication tag separately.
- **RSA:** OAEP/SHA-256 is used for encryption and PSS/SHA-256 for signatures.
  Key generation uses at least 2048-bit RSA keys.
- **DES/3DES:** Included for historical and legacy-data compatibility only.
  CBC mode is unauthenticated and must not be used for new applications.
- **Diffie–Hellman:** Establishes a shared secret. HKDF-SHA-256 derives
  symmetric key material from that secret.
- **ECC:** ECDH establishes shared secrets; ECDSA signs and verifies messages.
  HKDF derives symmetric key material from ECDH output.
- **Hashing:** MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 digest
  calculation is supported. bcrypt and Argon2 are used for password hashing
  and verification. Hash identification is heuristic.

## Important limitations

Modern decryption requires the correct keys and parameters. Diffie–Hellman and
ECDH are key-agreement mechanisms, not encryption algorithms. Hashes are not
decrypted. Password-hash auditing is limited to a supplied local wordlist and
candidate limit, and should only be used on hashes the user owns or is
authorized to audit.

The automatic candidate quality score is a heuristic, not proof of correctness.
Hash identification by length is ambiguous. Repeated AES-sized blocks are a
warning sign, not proof that a ciphertext uses AES-ECB. DES/3DES are obsolete.
Production systems should use established authenticated protocols and secure
key management rather than treating these educational APIs as a complete
replacement for TLS or a vetted cryptographic application.

## Validation

The project includes unit tests for the existing encoding, classical cipher,
XOR, candidate, scoring, reporting and search components. Additional tests cover
modern cryptographic round trips, signature verification, key agreement,
password-hash verification and digest identification. Optional dependency tests
are skipped when their package is not installed.
