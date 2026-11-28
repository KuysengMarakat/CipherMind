# CipherMind — Intelligent Cryptanalysis Toolkit

CipherMind is a local, educational Python toolkit for analyzing unknown data and
solving authorized CTF-style cryptography challenges. It combines input
intelligence, encoding decoders, classical cryptanalysis, XOR analysis,
candidate scoring, bounded multi-layer search, and explicit modern-cryptography
and hash utilities.

## Main capabilities

### Automatic cryptanalysis workflow

- Input statistics: length, character set, frequency, Shannon entropy and format hints.
- Encodings: Base64, Base32, Base58, Base85, hexadecimal, binary, octal, decimal,
  URL encoding, HTML entities and Morse code.
- Classical ciphers: Caesar, Atbash, Affine, Vigenère and substitution analysis.
- XOR: single-byte and repeating-key XOR analysis.
- Candidate scoring: printable ratio, common-word score, quadgram fitness and entropy.
- Bounded multi-layer search with depth, beam-width, state-count and time limits.
- CLI reporting with simple and detailed output modes.

### Explicit modern cryptography utilities

Modern algorithms are not blindly run as automatic candidates because they
require keys, nonces, IVs, public parameters or structured inputs.

- AES-GCM: key generation, authenticated encryption and decryption.
- RSA: key generation, OAEP encryption/decryption, PSS signatures and verification.
- DES/3DES: legacy CBC compatibility for educational use only.
- Diffie–Hellman: key agreement and HKDF session-key derivation.
- ECC: ECDH key agreement, HKDF session-key derivation and ECDSA signatures.
- Existing educational checks: repeated AES blocks, selected RSA weaknesses and
  heuristic hash-format identification.

### Hash utilities

- MD5, SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 digest calculation.
- Heuristic digest-format identification.
- bcrypt and Argon2 password-hash generation and verification.
- Bounded local wordlist auditing for bcrypt and Argon2 hashes.
- Automatic dictionary attempts for raw MD5, NTLM, SHA-1, SHA-224, SHA-256,
  SHA-384 and SHA-512 digests entered at the normal interactive prompt.

MD5 and SHA-1 are provided for legacy compatibility and learning, not for new
security-sensitive designs. Hashes are not decrypted: password hashes can only
be verified against candidate passwords.

## Requirements

- Python 3.10 or newer
- Install dependencies in a virtual environment (recommended on Pop!_OS and other
PEP 668-managed Linux distributions):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The modern cryptography modules use `cryptography`; password-hash functions use
`bcrypt` and `argon2-cffi`.

## Run the interactive cryptanalysis CLI

```bash
python3 main.py
```

The interactive prompt automatically checks for hash-like input before running
classical cryptanalysis. Raw hexadecimal digests are tested against a bounded
local dictionary; bcrypt and Argon2 hashes receive a smaller candidate budget
because each verification is intentionally expensive. A 32-character digest
may be MD5 or NTLM, so the matched algorithm is reported only after a candidate
is verified. If you know a raw hexadecimal value is encoded ciphertext or data
and want the normal decoding pipeline to try it, use:

```bash
python3 main.py --force-cryptanalysis
```

Hash detection is heuristic. Dictionary auditing tests candidate passwords;
it does not reverse or decrypt hashes. The bundled English wordlist and a small set of common password mutations
(capitalization and suffixes such as `!`, `@`, `1`, and `123`) are used for
fast raw digests. This is a bounded dictionary audit, not exhaustive brute force.
You can supply a larger authorized CTF wordlist with:

```bash
python3 main.py --hash-wordlist ./rockyou.txt
```

Or set `CIPHERMIND_WORDLIST` in your shell. The default limits are 50,000
candidates for fast raw digests and 25 for bcrypt/Argon2. Adjust them with
`--hash-max-candidates` and `--slow-hash-max-candidates`.

Show detailed input and candidate measurements:

```bash
python3 main.py --details --top 5
```

Run bounded multi-layer search:

```bash
python3 main.py --search --depth 3 --beam-width 5 --max-states 100 --time-budget 5
```

If a challenge has a known flag format:

```bash
python3 main.py --search --flag-pattern 'CTF\\{[^}]+\\}'
```

## Modern cryptography examples

Generate an AES-256 key:

```bash
python3 main.py crypto aes keygen --bits 256
```

Encrypt text with AES-GCM:

```bash
python3 main.py crypto aes encrypt --key-hex YOUR_KEY_HEX --text "Hello CipherMind"
```

The command returns a nonce, ciphertext and authentication tag. Use all three
with the same key to decrypt:

```bash
python3 main.py crypto aes decrypt \
  --key-hex YOUR_KEY_HEX \
  --nonce-hex NONCE_HEX \
  --ciphertext-hex CIPHERTEXT_HEX \
  --tag-hex TAG_HEX
```

Generate RSA keys:

```bash
python3 main.py crypto rsa keygen \
  --private-out private.pem \
  --public-out public.pem \
  --bits 2048 \
  --protect-private-key
```

The private-key passphrase is requested interactively. Keep the private key
secret and backed up securely.

RSA encryption/decryption:

```bash
python3 main.py crypto rsa encrypt --public-key public.pem --text "Small message"
python3 main.py crypto rsa decrypt --private-key private.pem --protected --ciphertext-hex CIPHERTEXT_HEX
```

Demonstrate Diffie–Hellman:

```bash
python3 main.py crypto dh demo
```

Demonstrate ECDH and ECDSA:

```bash
python3 main.py crypto ecc demo --curve secp256r1
```

DES/3DES are available only for legacy educational compatibility:

```bash
python3 main.py crypto des --algorithm 3des keygen
```

Do not use DES or 3DES for new applications. Prefer AES-GCM.

## Hash examples

Calculate SHA-256:

```bash
python3 main.py hash digest --algorithm sha256 --text "Hello World"
```

Identify a possible digest format:

```bash
python3 main.py hash identify --value YOUR_HASH
```

Create an Argon2 password hash (the password is requested without echo):

```bash
python3 main.py hash password-hash --algorithm argon2
```

Verify a password against an encoded bcrypt or Argon2 hash:

```bash
python3 main.py hash verify --encoded-hash 'YOUR_ENCODED_HASH'
```

Run a bounded local wordlist audit on a hash you own or are authorized to test:

```bash
python3 main.py hash audit \
  --encoded-hash 'YOUR_ENCODED_HASH' \
  --wordlist ./authorized-test-passwords.txt \
  --max-candidates 10000
```

Hash identification is heuristic. Several digest algorithms share the same
length, and a length match does not prove which algorithm produced the value.

## Run tests

```bash
python3 -m compileall -q .
python3 -m unittest discover -s tests -v
```

## Security and scope notes

- AES-GCM is the recommended symmetric-encryption interface in this project.
  Never reuse a nonce with the same AES-GCM key.
- RSA uses OAEP for encryption and PSS for signatures. RSA is intended for small
  payloads; use hybrid encryption (RSA to wrap an AES key) for larger data.
- Diffie–Hellman and ECDH establish shared secrets; they do not encrypt messages
  by themselves. Production protocols must authenticate peers to prevent
  man-in-the-middle attacks.
- DES and 3DES are obsolete. Their support is for historical study and legacy
  interoperability only.
- MD5 and SHA-1 are weak for modern security use. bcrypt and Argon2 are the
  password-hashing options in this toolkit.
- A high plaintext quality score is heuristic, not proof that a result is
  correct. Use known plaintext, a CTF flag pattern, authentication tag, signature
  verification or another independent validation rule when available.
- Use the toolkit only on data, keys and password hashes you own or are
  explicitly authorized to analyze.
