# Modern cryptography and hashing in CipherMind

This document explains the modern tools added to CipherMind.

## 1. AES-GCM

AES is a symmetric block cipher: the same secret key is used to encrypt and
decrypt. CipherMind exposes AES-GCM because GCM provides both confidentiality
and integrity. The output consists of a nonce, ciphertext and authentication
tag. The nonce is not secret, but it must never be reused with the same key.
Decryption fails if the key, nonce, ciphertext, tag or associated data is wrong.

AES-GCM is not automatically selected by Candidate Generation. An unknown
ciphertext alone does not provide the key and nonce required for decryption.

## 2. RSA

RSA is public-key cryptography. A public key can encrypt or verify signatures;
the matching private key can decrypt or create signatures. CipherMind uses
OAEP/SHA-256 for encryption and PSS/SHA-256 for signatures. RSA encryption is
suitable for small payloads. Larger data should use hybrid encryption, where
RSA wraps a randomly generated AES key and AES-GCM encrypts the actual data.

The existing `rsa_checks.py` module remains an educational weakness-analysis
module. Exact small-exponent roots, Fermat factorization and shared-factor
checks only apply to particular weak challenge parameters; they do not break
properly generated RSA keys.

## 3. DES and 3DES

DES uses an 8-byte key and 8-byte block. 3DES applies DES multiple times.
Both are obsolete and are included only for learning and legacy compatibility.
CipherMind's CBC helpers use PKCS7 padding. CBC does not authenticate ciphertext;
AES-GCM is preferred for new designs.

## 4. Diffie–Hellman

Diffie–Hellman allows two parties to derive the same shared secret over a
public channel. It does not encrypt a message and does not authenticate the
participants. The toolkit uses a 2048-bit parameter set by default and applies
HKDF-SHA-256 to derive session-key material from the raw shared secret.
Production systems need authenticated key exchange, normally through a
well-reviewed protocol such as TLS.

## 5. Elliptic-curve cryptography

CipherMind demonstrates:
- ECDH: elliptic-curve Diffie–Hellman shared-secret agreement.
- ECDSA: elliptic-curve digital signatures.

Supported curves are secp256r1, secp384r1 and secp521r1. ECDH output is passed
through HKDF before being used as a symmetric key.

## 6. Hash functions and password hashing

MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 produce fixed-length
digests. They are not encryption and cannot be decrypted. MD5 and SHA-1 are
included for compatibility, not recommended security use.

bcrypt and Argon2 are password-hashing schemes. They use salts and configurable
work factors. CipherMind can generate hashes, verify a supplied password, and
perform a bounded local wordlist audit. A failed wordlist audit does not prove
that a password is unrecoverable; it only means no tested word matched.

The normal interactive prompt also attempts a bounded dictionary audit for raw
MD5, NTLM, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 digests. It uses a small
common-candidate list followed by the bundled English dictionary. An optional
local wordlist can be provided with `--hash-wordlist` or `CIPHERMIND_WORDLIST`.
For bcrypt and Argon2, the automatic candidate budget is much smaller because
these algorithms are intentionally expensive to verify.

Hash-format identification is heuristic. For example, a 32-character
hexadecimal digest could be MD5 or NTLM; length alone cannot prove which one.
CipherMind tests each possible format against candidates and reports the
algorithm only when a candidate matches. Hashes are never decrypted.

## 7. Commands

See the project README for full commands. Examples:

```bash
python3 main.py crypto aes keygen --bits 256
python3 main.py crypto dh demo
python3 main.py crypto ecc demo
python3 main.py hash digest --algorithm sha256 --text "hello"
python3 main.py hash identify --value YOUR_HASH
python3 main.py hash password-hash --algorithm argon2
```

## 8. Security reminders

Use these tools only with data and keys you own or are authorized to analyze.
Keep private keys secret. Do not reuse AES-GCM nonces with the same key. Do not
use DES/3DES or MD5/SHA-1 for new security-sensitive designs. Do not mistake
heuristic identification or statistical ranking for cryptographic proof.
