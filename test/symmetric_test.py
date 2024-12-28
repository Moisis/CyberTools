import unittest

from Modules.AES import SymmetricEncryption
from Crypto.Random import get_random_bytes


class TestSymmetricEncryption(unittest.TestCase):
    def setUp(self):
        self.plaintext = b"Hello, AES Encryption!"
        self.custom_key = get_random_bytes(16)
        self.encryption_obj = SymmetricEncryption()
        self.custom_encryption_obj = SymmetricEncryption(key=self.custom_key)

    def test_encryption_and_decryption(self):
        ciphertext, tag, nonce = self.encryption_obj.encrypt(self.plaintext)
        decrypted_text = self.encryption_obj.decrypt(ciphertext, tag, nonce)
        self.assertEqual(self.plaintext, decrypted_text)

    def test_custom_key_encryption_and_decryption(self):
        ciphertext, tag, nonce = self.custom_encryption_obj.encrypt(self.plaintext)
        decrypted_text = self.custom_encryption_obj.decrypt(ciphertext, tag, nonce)
        self.assertEqual(self.plaintext, decrypted_text)

    def test_multiple_encryptions_with_same_key(self):
        plaintext2 = b"Second message"
        ciphertext1, tag1, nonce1 = self.encryption_obj.encrypt(self.plaintext)
        ciphertext2, tag2, nonce2 = self.encryption_obj.encrypt(plaintext2)

        decrypted_text1 = self.encryption_obj.decrypt(ciphertext1, tag1, nonce1)
        decrypted_text2 = self.encryption_obj.decrypt(ciphertext2, tag2, nonce2)

        self.assertEqual(self.plaintext, decrypted_text1)
        self.assertEqual(plaintext2, decrypted_text2)

    def test_empty_plaintext(self):
        empty_plaintext = b""
        ciphertext, tag, nonce = self.encryption_obj.encrypt(empty_plaintext)
        decrypted_text = self.encryption_obj.decrypt(ciphertext, tag, nonce)
        self.assertEqual(empty_plaintext, decrypted_text)

    def test_tampered_ciphertext(self):
        ciphertext, tag, nonce = self.encryption_obj.encrypt(self.plaintext)
        tampered_ciphertext = ciphertext[:-1] + (b'\x00' if ciphertext[-1] != 0 else b'\x01')

        with self.assertRaises(ValueError):
            self.encryption_obj.decrypt(tampered_ciphertext, tag, nonce)
