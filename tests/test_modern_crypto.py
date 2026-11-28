import unittest

from cryptography.hazmat.primitives import serialization

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


class ModernCryptoTests(unittest.TestCase):
    def test_aes_gcm_round_trip_and_authentication(self):
        key = generate_aes_key(256)
        result = aes_gcm_encrypt(key, b"CipherMind AES test", associated_data=b"header")
        plaintext = aes_gcm_decrypt(
            key, result["nonce"], result["ciphertext"], result["tag"],
            associated_data=b"header",
        )
        self.assertEqual(plaintext, b"CipherMind AES test")
        with self.assertRaises(Exception):
            aes_gcm_decrypt(
                key, result["nonce"], result["ciphertext"], result["tag"],
                associated_data=b"wrong header",
            )

    def test_aes_rejects_invalid_key_size(self):
        with self.assertRaises(ValueError):
            aes_gcm_encrypt(b"short", b"data")

    def test_des_round_trip_legacy(self):
        key = bytes.fromhex("133457799BBCDFF1")
        iv = b"12345678"
        ciphertext = des_cbc_encrypt(key, iv, b"Legacy DES")
        self.assertEqual(des_cbc_decrypt(key, iv, ciphertext), b"Legacy DES")

    def test_triple_des_round_trip_legacy(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA98765432100011223344556677")
        iv = b"87654321"
        ciphertext = triple_des_cbc_encrypt(key, iv, b"Legacy 3DES")
        self.assertEqual(triple_des_cbc_decrypt(key, iv, ciphertext), b"Legacy 3DES")

    def test_rsa_oaep_and_pss(self):
        private_pem, public_pem = generate_rsa_keypair(2048)
        ciphertext = rsa_oaep_encrypt(public_pem, b"RSA test")
        self.assertEqual(rsa_oaep_decrypt(private_pem, ciphertext), b"RSA test")
        signature = rsa_pss_sign(private_pem, b"message")
        self.assertTrue(rsa_pss_verify(public_pem, b"message", signature))
        self.assertFalse(rsa_pss_verify(public_pem, b"changed", signature))

    def test_rsa_encrypted_private_key(self):
        private_pem, public_pem = generate_rsa_keypair(2048, b"passphrase")
        ciphertext = rsa_oaep_encrypt(public_pem, b"secret")
        self.assertEqual(
            rsa_oaep_decrypt(private_pem, ciphertext, password=b"passphrase"),
            b"secret",
        )

    def test_diffie_hellman_agreement(self):
        parameters = generate_dh_parameters(2048)
        loaded = serialization.load_pem_parameters(parameters)
        self.assertEqual(loaded.parameter_numbers().p.bit_length(), 2048)
        alice_private, alice_public = generate_dh_keypair(parameters)
        bob_private, bob_public = generate_dh_keypair(parameters)
        alice_secret = derive_dh_shared_secret(alice_private, bob_public)
        bob_secret = derive_dh_shared_secret(bob_private, alice_public)
        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(
            derive_dh_session_key(alice_secret),
            derive_dh_session_key(bob_secret),
        )

    def test_ecdh_and_ecdsa(self):
        alice_private, alice_public = generate_ec_keypair("secp256r1")
        bob_private, bob_public = generate_ec_keypair("secp256r1")
        alice_secret = ecdh_shared_secret(alice_private, bob_public)
        bob_secret = ecdh_shared_secret(bob_private, alice_public)
        self.assertEqual(alice_secret, bob_secret)
        self.assertEqual(
            derive_ecdh_session_key(alice_secret),
            derive_ecdh_session_key(bob_secret),
        )
        signature = ecdsa_sign(alice_private, b"CipherMind")
        self.assertTrue(ecdsa_verify(alice_public, b"CipherMind", signature))
        self.assertFalse(ecdsa_verify(alice_public, b"modified", signature))

    def test_ecdh_rejects_different_curves(self):
        alice_private, _ = generate_ec_keypair("secp256r1")
        _, peer_public = generate_ec_keypair("secp384r1")
        with self.assertRaises(ValueError):
            ecdh_shared_secret(alice_private, peer_public)


if __name__ == "__main__":
    unittest.main()
