# CipherMind architecture

```text
main.py
  ├── Interactive cryptanalysis workflow
  │     ├── input_intelligence
  │     │     ├── analyzer.py
  │     │     ├── input_stats.py
  │     │     └── format_detector.py
  │     ├── CandidateGenerator
  │     │     └── candidate_generation.py
  │     ├── plugins
  │     │     ├── registry.py
  │     │     └── encoding/classical/XOR plugins
  │     ├── core
  │     │     ├── pipeline.py
  │     │     ├── search.py
  │     │     └── models.py
  │     ├── scoring
  │     │     ├── scorer.py
  │     │     ├── word_score.py
  │     │     ├── quadgram_score.py
  │     │     ├── printable_score.py
  │     │     ├── entropy_score.py
  │     │     └── ranking.py
  │     └── reporting
  │
  └── Explicit modern commands (`crypto` and `hash`)
        └── modern
              ├── aes.py              AES-GCM
              ├── legacy_des.py       DES/3DES legacy CBC
              ├── rsa.py              RSA-OAEP and RSA-PSS
              ├── diffie_hellman.py   DH key agreement and HKDF
              ├── ecc.py              ECDH, ECDSA and HKDF
              ├── hashing.py          digests, bcrypt, Argon2, auditing
              ├── hash_identifier.py  heuristic format hints
              ├── aes_checks.py       repeated-block checks
              └── rsa_checks.py       selected RSA weakness checks
```

## Why modern cryptography is a separate execution path

The classical candidate engine is suitable for trying transformations such as
Base64, Caesar and Affine because those operations can be attempted against
unknown input using a bounded list of possibilities.

Modern cryptographic operations have different requirements:

- AES decryption needs the correct key, nonce/IV, mode and (for AEAD) tag.
- RSA decryption needs the matching private key and correct padding scheme.
- DES/3DES decryption needs a key, IV and mode.
- Diffie–Hellman and ECDH establish a shared secret; they do not decrypt a
  ciphertext directly.
- ECDSA and RSA-PSS verify signatures using a public key.
- Hashes are one-way digests. Password hashes are verified against candidate
  passwords, not decrypted.

For these reasons, the modern tools are exposed through explicit CLI commands
and Python APIs rather than being registered as ordinary automatic decryption
plugins. This avoids misleading attempts and makes key/parameter requirements
visible to the user.

## Existing candidate workflow

Plugins expose `detect`, `apply`, `cost`, `input_mode` and `explain`. The
Candidate Generator checks cost, input compatibility and suitability. The core
pipeline executes selected candidates, scores their outputs, ranks results and
removes duplicate outputs. The bounded search engine can chain supported
transformations under depth, beam-width, state-count and time limits.

## Security design

AES-GCM is used for authenticated symmetric encryption. RSA uses OAEP for
encryption and PSS for signatures. ECDH/DH outputs are passed through HKDF
before being used as symmetric key material. DES/3DES are marked legacy only.
MD5/SHA-1 are included for compatibility and learning, while Argon2id and
bcrypt are used for password hashing.

Search and scoring results remain heuristic unless independently verified.
