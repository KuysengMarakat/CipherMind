"""Elliptic-curve key agreement (ECDH) and signatures (ECDSA)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_CURVES = {
    "secp256r1": ec.SECP256R1,
    "secp384r1": ec.SECP384R1,
    "secp521r1": ec.SECP521R1,
}


def _curve_from_name(name):
    try:
        return _CURVES[name.lower()]()
    except (AttributeError, KeyError):
        raise ValueError("Supported curves: secp256r1, secp384r1, secp521r1")


def generate_ec_keypair(curve="secp256r1"):
    """Return (private_key_pem, public_key_pem) for ECDH or ECDSA."""
    private_key = ec.generate_private_key(_curve_from_name(curve))
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def ecdh_shared_secret(private_key_pem, peer_public_key_pem):
    """Derive an ECDH shared secret from PEM-encoded EC keys."""
    if not isinstance(private_key_pem, bytes) or not isinstance(peer_public_key_pem, bytes):
        raise TypeError("EC keys must be PEM bytes")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    peer_key = serialization.load_pem_public_key(peer_public_key_pem)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Private key must be an EC private key")
    if not isinstance(peer_key, ec.EllipticCurvePublicKey):
        raise TypeError("Peer key must be an EC public key")
    if private_key.curve.name != peer_key.curve.name:
        raise ValueError("ECDH keys must use the same curve")
    return private_key.exchange(ec.ECDH(), peer_key)


def derive_ecdh_session_key(shared_secret, length=32, salt=None, info=b"CipherMind ECDH session key"):
    """Derive symmetric key material from an ECDH shared secret using HKDF."""
    if not isinstance(shared_secret, bytes) or not shared_secret:
        raise ValueError("Shared secret must be non-empty bytes")
    if not isinstance(length, int) or not 1 <= length <= 255 * 32:
        raise ValueError("HKDF output length must be between 1 and 8160 bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


def ecdsa_sign(private_key_pem, message):
    """Sign a message using ECDSA/SHA-256."""
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Private key must be an EC private key")
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ecdsa_verify(public_key_pem, message, signature):
    """Return True if an ECDSA/SHA-256 signature is valid."""
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise TypeError("Message and signature must be bytes")
    public_key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Public key must be an EC public key")
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
