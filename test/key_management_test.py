import unittest
from Crypto.PublicKey import RSA
from Modules import KeyManagement


class TestKeyManagement(unittest.TestCase):
    def setUp(self):
        self.email_sender = "sender@example.com"
        self.email_receiver = "receiver@example.com"

        # Generate RSA key pairs for sender and receiver
        self.private_key_sender = KeyManagement.get_rsa_private_key(self.email_sender)
        self.public_key_sender = KeyManagement.get_rsa_public_key(self.email_sender)

        self.private_key_receiver = KeyManagement.get_rsa_private_key(self.email_receiver)
        self.public_key_receiver = KeyManagement.get_rsa_public_key(self.email_receiver)

        self.test_data = b"This is a test message."

    def test_generate_rsa_key_pair(self):
        """Test RSA key pair generation and file saving."""
        key, public_key = KeyManagement.generate_rsa_key_pair("test@example.com")
        self.assertIsInstance(key, RSA.RsaKey)
        self.assertIsInstance(public_key, RSA.RsaKey)

    def test_double_encrypt_and_decrypt(self):
        """Test double encryption and decryption."""
        encrypted_data = KeyManagement.double_encrypt(
            self.test_data,
            private_key_sender=self.private_key_sender,
            public_key_receiver=self.public_key_receiver,
        )

        decrypted_data = KeyManagement.double_decrypt(
            encrypted_data,
            private_key_receiver=self.private_key_receiver,
            public_key_sender=self.public_key_sender,
        )

        self.assertEqual(self.test_data, decrypted_data)

    def test_signature_verification_failure(self):
        """Test that signature verification fails for tampered data."""
        encrypted_data = KeyManagement.double_encrypt(
            self.test_data,
            private_key_sender=self.private_key_sender,
            public_key_receiver=self.public_key_receiver,
        )

        tampered_data = encrypted_data[:-5] + "xyz"  # Tamper with encrypted data

        with self.assertRaises(ValueError):
            KeyManagement.double_decrypt(
                tampered_data,
                private_key_receiver=self.private_key_receiver,
                public_key_sender=self.public_key_sender,
            )

    def test_generate_symmetric_session_key(self):
        """Test symmetric session key generation."""
        session_key = KeyManagement.generate_symmetric_session_key()
        self.assertEqual(len(session_key), 16)  # 16 bytes = 128 bits
