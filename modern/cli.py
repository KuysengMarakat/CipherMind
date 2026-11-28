"""Command-line helpers for CipherMind's modern cryptography and hash tools."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import sys

from modern.aes import generate_aes_key, aes_gcm_encrypt, aes_gcm_decrypt
from modern.legacy_des import (
    des_cbc_encrypt, des_cbc_decrypt,
    triple_des_cbc_encrypt, triple_des_cbc_decrypt,
)
from modern.rsa import (
    generate_rsa_keypair, rsa_oaep_encrypt, rsa_oaep_decrypt,
    rsa_pss_sign, rsa_pss_verify,
)
from modern.diffie_hellman import (
    generate_dh_parameters, generate_dh_keypair,
    derive_dh_shared_secret, derive_dh_session_key,
)
from modern.ecc import (
    generate_ec_keypair, ecdh_shared_secret,
    derive_ecdh_session_key, ecdsa_sign, ecdsa_verify,
)
from modern.hashing import (
    calculate_digest, hash_password_bcrypt, verify_password_hash,
    hash_password_argon2, audit_password_hash,
)
from modern.hash_identifier import identify_hash


def _hex(value, name):
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be valid hexadecimal") from exc


def _read(path, name):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ValueError(f"Cannot read {name} file {path!r}: {exc}") from exc


def _write_private(path, data):
    target = Path(path)
    target.write_bytes(data)
    try:
        target.chmod(0o600)
    except OSError:
        pass


def build_modern_parser():
    parser = argparse.ArgumentParser(
        prog="python3 main.py",
        description="CipherMind modern cryptography and hash utilities",
    )
    groups = parser.add_subparsers(dest="group", required=True)

    crypto = groups.add_parser("crypto", help="Modern and legacy cryptography")
    crypto_commands = crypto.add_subparsers(dest="family", required=True)

    # AES-GCM
    aes = crypto_commands.add_parser("aes", help="AES-GCM encryption/decryption")
    aes_commands = aes.add_subparsers(dest="action", required=True)
    aes_keygen = aes_commands.add_parser("keygen")
    aes_keygen.add_argument("--bits", type=int, choices=(128, 192, 256), default=256)
    aes_encrypt = aes_commands.add_parser("encrypt")
    aes_encrypt.add_argument("--key-hex", required=True)
    aes_encrypt.add_argument("--text", required=True)
    aes_encrypt.add_argument("--aad", default=None)
    aes_decrypt = aes_commands.add_parser("decrypt")
    aes_decrypt.add_argument("--key-hex", required=True)
    aes_decrypt.add_argument("--nonce-hex", required=True)
    aes_decrypt.add_argument("--ciphertext-hex", required=True)
    aes_decrypt.add_argument("--tag-hex", required=True)
    aes_decrypt.add_argument("--aad", default=None)

    # Legacy DES/3DES
    des = crypto_commands.add_parser("des", help="Legacy DES/3DES CBC (educational only)")
    des.add_argument("--algorithm", choices=("des", "3des"), required=True)
    des_commands = des.add_subparsers(dest="action", required=True)
    des_keygen = des_commands.add_parser("keygen")
    des_encrypt = des_commands.add_parser("encrypt")
    des_encrypt.add_argument("--key-hex", required=True)
    des_encrypt.add_argument("--iv-hex", default=None)
    des_encrypt.add_argument("--text", required=True)
    des_decrypt = des_commands.add_parser("decrypt")
    des_decrypt.add_argument("--key-hex", required=True)
    des_decrypt.add_argument("--iv-hex", required=True)
    des_decrypt.add_argument("--ciphertext-hex", required=True)

    # RSA
    rsa = crypto_commands.add_parser("rsa", help="RSA-OAEP and RSA-PSS")
    rsa_commands = rsa.add_subparsers(dest="action", required=True)
    rsa_keygen = rsa_commands.add_parser("keygen")
    rsa_keygen.add_argument("--private-out", required=True)
    rsa_keygen.add_argument("--public-out", required=True)
    rsa_keygen.add_argument("--bits", type=int, default=2048)
    rsa_keygen.add_argument("--protect-private-key", action="store_true")
    rsa_encrypt = rsa_commands.add_parser("encrypt")
    rsa_encrypt.add_argument("--public-key", required=True)
    rsa_encrypt.add_argument("--text", required=True)
    rsa_decrypt = rsa_commands.add_parser("decrypt")
    rsa_decrypt.add_argument("--private-key", required=True)
    rsa_decrypt.add_argument("--ciphertext-hex", required=True)
    rsa_decrypt.add_argument("--protected", action="store_true", help="Prompt for a private-key passphrase")
    rsa_sign = rsa_commands.add_parser("sign")
    rsa_sign.add_argument("--private-key", required=True)
    rsa_sign.add_argument("--text", required=True)
    rsa_sign.add_argument("--protected", action="store_true", help="Prompt for a private-key passphrase")
    rsa_verify = rsa_commands.add_parser("verify")
    rsa_verify.add_argument("--public-key", required=True)
    rsa_verify.add_argument("--text", required=True)
    rsa_verify.add_argument("--signature-hex", required=True)

    # DH and ECC demonstrations
    dh = crypto_commands.add_parser("dh", help="Diffie-Hellman key agreement demonstration")
    dh_commands = dh.add_subparsers(dest="action", required=True)
    dh_demo = dh_commands.add_parser("demo")
    dh_demo.add_argument("--bits", type=int, default=2048)

    ecc = crypto_commands.add_parser("ecc", help="Elliptic-curve cryptography")
    ecc_commands = ecc.add_subparsers(dest="action", required=True)
    ecc_demo = ecc_commands.add_parser("demo")
    ecc_demo.add_argument("--curve", choices=("secp256r1", "secp384r1", "secp521r1"), default="secp256r1")

    # Hashing
    hashing = groups.add_parser("hash", help="Digest and password-hash utilities")
    hash_commands = hashing.add_subparsers(dest="action", required=True)
    digest = hash_commands.add_parser("digest")
    digest.add_argument("--algorithm", choices=("md5", "sha1", "sha224", "sha256", "sha384", "sha512"), default="sha256")
    digest.add_argument("--text", required=True)
    identify = hash_commands.add_parser("identify")
    identify.add_argument("--value", required=True)
    password_hash = hash_commands.add_parser("password-hash")
    password_hash.add_argument("--algorithm", choices=("bcrypt", "argon2"), required=True)
    verify = hash_commands.add_parser("verify")
    verify.add_argument("--encoded-hash", required=True)
    audit = hash_commands.add_parser("audit")
    audit.add_argument("--encoded-hash", required=True)
    audit.add_argument("--wordlist", required=True)
    audit.add_argument("--max-candidates", type=int, default=100000)

    return parser


def _run_crypto(args):
    if args.family == "aes":
        if args.action == "keygen":
            key = generate_aes_key(args.bits)
            print(f"AES-{args.bits} key (hex): {key.hex()}")
            print("Keep this key secret. Never reuse a GCM nonce with the same key.")
        elif args.action == "encrypt":
            key = _hex(args.key_hex, "AES key")
            result = aes_gcm_encrypt(
                key, args.text.encode("utf-8"),
                associated_data=args.aad.encode("utf-8") if args.aad is not None else None,
            )
            print(json.dumps({name: value.hex() if isinstance(value, bytes) else value for name, value in result.items()}, indent=2))
        else:
            key = _hex(args.key_hex, "AES key")
            plaintext = aes_gcm_decrypt(
                key,
                _hex(args.nonce_hex, "nonce"),
                _hex(args.ciphertext_hex, "ciphertext"),
                _hex(args.tag_hex, "tag"),
                associated_data=args.aad.encode("utf-8") if args.aad is not None else None,
            )
            try:
                print(plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"Binary plaintext (hex): {plaintext.hex()}")
        return 0

    if args.family == "des":
        if args.action == "keygen":
            length = 8 if args.algorithm == "des" else 24
            print(f"{args.algorithm.upper()} key (hex): {os.urandom(length).hex()}")
            print("WARNING: DES/3DES are obsolete. Use AES-GCM for new applications.")
            return 0
        key = _hex(args.key_hex, "key")
        if args.algorithm == "des":
            encrypt, decrypt = des_cbc_encrypt, des_cbc_decrypt
        else:
            encrypt, decrypt = triple_des_cbc_encrypt, triple_des_cbc_decrypt
        if args.action == "encrypt":
            iv = _hex(args.iv_hex, "IV") if args.iv_hex else os.urandom(8)
            ciphertext = encrypt(key, iv, args.text.encode("utf-8"))
            print(json.dumps({"iv_hex": iv.hex(), "ciphertext_hex": ciphertext.hex()}, indent=2))
            print("WARNING: DES/3DES-CBC provides no authentication and is for legacy use only.")
        else:
            plaintext = decrypt(key, _hex(args.iv_hex, "IV"), _hex(args.ciphertext_hex, "ciphertext"))
            try:
                print(plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"Binary plaintext (hex): {plaintext.hex()}")
        return 0

    if args.family == "rsa":
        if args.action == "keygen":
            passphrase = None
            if args.protect_private_key:
                first = getpass.getpass("Private-key passphrase: ")
                second = getpass.getpass("Confirm passphrase: ")
                if not first or first != second:
                    raise ValueError("Passphrases must be non-empty and match")
                passphrase = first.encode("utf-8")
            private_pem, public_pem = generate_rsa_keypair(args.bits, passphrase)
            _write_private(args.private_out, private_pem)
            Path(args.public_out).write_bytes(public_pem)
            print(f"Private key saved: {args.private_out} (permissions set to owner-only where supported)")
            print(f"Public key saved : {args.public_out}")
            if not args.protect_private_key:
                print("WARNING: The private key is not passphrase-encrypted. Protect this file.")
        elif args.action == "encrypt":
            ciphertext = rsa_oaep_encrypt(_read(args.public_key, "public key"), args.text.encode("utf-8"))
            print(ciphertext.hex())
        elif args.action == "decrypt":
            password = getpass.getpass("Private-key passphrase: ").encode("utf-8") if args.protected else None
            plaintext = rsa_oaep_decrypt(
                _read(args.private_key, "private key"),
                _hex(args.ciphertext_hex, "ciphertext"),
                password=password,
            )
            try:
                print(plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                print(f"Binary plaintext (hex): {plaintext.hex()}")
        elif args.action == "sign":
            password = getpass.getpass("Private-key passphrase: ").encode("utf-8") if args.protected else None
            signature = rsa_pss_sign(
                _read(args.private_key, "private key"),
                args.text.encode("utf-8"),
                password=password,
            )
            print(signature.hex())
        else:
            valid = rsa_pss_verify(
                _read(args.public_key, "public key"),
                args.text.encode("utf-8"),
                _hex(args.signature_hex, "signature"),
            )
            print("Signature valid" if valid else "Signature INVALID")
        return 0

    if args.family == "dh":
        if args.action == "demo":
            parameters = generate_dh_parameters(args.bits)
            alice_private, alice_public = generate_dh_keypair(parameters)
            bob_private, bob_public = generate_dh_keypair(parameters)
            alice_secret = derive_dh_shared_secret(alice_private, bob_public)
            bob_secret = derive_dh_shared_secret(bob_private, alice_public)
            if alice_secret != bob_secret:
                raise RuntimeError("Diffie-Hellman shared secrets did not match")
            session_key = derive_dh_session_key(alice_secret)
            print("Diffie-Hellman key agreement successful.")
            print(f"Parameter size : {args.bits} bits")
            print("Both parties derived the same shared secret.")
            print(f"Derived key SHA-256 fingerprint: {hashlib.sha256(session_key).hexdigest()}")
            print("Note: DH establishes a secret; it does not encrypt or authenticate messages.")
        return 0

    if args.family == "ecc":
        if args.action == "demo":
            alice_private, alice_public = generate_ec_keypair(args.curve)
            bob_private, bob_public = generate_ec_keypair(args.curve)
            alice_secret = ecdh_shared_secret(alice_private, bob_public)
            bob_secret = ecdh_shared_secret(bob_private, alice_public)
            if alice_secret != bob_secret:
                raise RuntimeError("ECDH shared secrets did not match")
            session_key = derive_ecdh_session_key(alice_secret)
            signature = ecdsa_sign(alice_private, b"CipherMind ECC demonstration")
            verified = ecdsa_verify(alice_public, b"CipherMind ECC demonstration", signature)
            print("Elliptic-curve demonstration successful.")
            print(f"Curve           : {args.curve}")
            print("ECDH agreement  : successful")
            print(f"Derived key SHA-256 fingerprint: {hashlib.sha256(session_key).hexdigest()}")
            print(f"ECDSA signature : {'valid' if verified else 'INVALID'}")
        return 0

    raise ValueError("Unsupported cryptography command")


def _run_hash(args):
    if args.action == "digest":
        result = calculate_digest(args.text, args.algorithm)
        print(f"Algorithm: {args.algorithm.upper()}")
        print(f"Digest   : {result}")
        if args.algorithm in ("md5", "sha1"):
            print("Warning: This digest is included for compatibility; it is not recommended for security-sensitive use.")
        return 0

    if args.action == "identify":
        matches = identify_hash(args.value)
        print("Possible format(s): " + (", ".join(matches) if matches else "No supported format recognized"))
        if matches:
            print("Note: Format identification is heuristic and cannot prove the original algorithm.")
        return 0

    if args.action == "password-hash":
        password = getpass.getpass("Password to hash: ")
        if not password:
            raise ValueError("Password cannot be empty")
        if args.algorithm == "bcrypt":
            encoded = hash_password_bcrypt(password)
        else:
            encoded = hash_password_argon2(password)
        print(f"{args.algorithm.upper()} encoded hash:")
        print(encoded)
        return 0

    if args.action == "verify":
        password = getpass.getpass("Password to verify: ")
        valid = verify_password_hash(password, args.encoded_hash)
        print("Password matches" if valid else "Password does not match")
        return 0 if valid else 1

    if args.action == "audit":
        result = audit_password_hash(
            args.encoded_hash,
            args.wordlist,
            max_candidates=args.max_candidates,
        )
        print(f"Algorithm : {result['algorithm']}")
        print(f"Candidates: {result['tested']}")
        if result["matched"]:
            print(f"Match     : {result['candidate']}")
        else:
            print("No match found in the supplied wordlist and candidate limit.")
        return 0

    raise ValueError("Unsupported hash command")


def run_modern_cli(argv=None):
    """Run a modern crypto/hash subcommand. Returns a process exit code."""
    parser = build_modern_parser()
    args = parser.parse_args(argv)
    try:
        if args.group == "crypto":
            return _run_crypto(args)
        return _run_hash(args)
    except Exception as error:
        # Keep cryptographic failures (for example, an invalid AES-GCM tag or
        # incorrect RSA key) readable in the CLI instead of showing a traceback.
        detail = str(error) or error.__class__.__name__
        print(f"CipherMind error: {detail}", file=sys.stderr)
        return 2
