"""RSA encryption and digital signatures using modern padding.

Use OAEP with SHA-256 for encryption and PSS with SHA-256 for signatures.
These functions require the correct private/public key; RSA is not a
keyless automatic decryption algorithm.
"""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(key_size=2048, passphrase=None):
    """Return (private_pem, public_pem). 2048 bits is the minimum default."""
    if not isinstance(key_size, int) or key_size < 2048 or key_size % 256:
        raise ValueError("RSA key size must be at least 2048 and a multiple of 256")
    if passphrase is not None and not isinstance(passphrase, bytes):
        raise TypeError("Passphrase must be bytes or None")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    encryption = (
        serialization.NoEncryption()
        if passphrase is None
        else serialization.BestAvailableEncryption(passphrase)
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _load_public_key(key):
    if isinstance(key, bytes):
        key = serialization.load_pem_public_key(key)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("Expected an RSA public key or PEM bytes")
    return key


def _load_private_key(key, password=None):
    if isinstance(key, bytes):
        key = serialization.load_pem_private_key(key, password=password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected an RSA private key or PEM bytes")
    return key


def rsa_oaep_encrypt(public_key, plaintext):
    """Encrypt bytes with RSA-OAEP/SHA-256."""
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    key = _load_public_key(public_key)
    return key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_oaep_decrypt(private_key, ciphertext, password=None):
    """Decrypt RSA-OAEP/SHA-256 bytes with the matching private key."""
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    key = _load_private_key(private_key, password=password)
    return key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_pss_sign(private_key, message, password=None):
    """Sign bytes using RSA-PSS/SHA-256."""
    if not isinstance(message, bytes):
        raise TypeError("Message must be bytes")
    key = _load_private_key(private_key, password=password)
    return key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key, message, signature):
    """Return True for a valid RSA-PSS signature, otherwise False."""
    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        raise TypeError("Message and signature must be bytes")
    key = _load_public_key(public_key)
    try:
        key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False
