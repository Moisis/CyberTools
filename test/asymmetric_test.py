import unittest
from Crypto.Random import get_random_bytes
from Modules.RSA import AsymmetricEncryption


class TestAsymmetricEncryption(unittest.TestCase):
    def setUp(self):
        self.plaintext = b"Hello, RSA Encryption!"
        self.encryption_obj = AsymmetricEncryption()

    def test_encryption_and_decryption(self):
        ciphertext = self.encryption_obj.encrypt(self.plaintext)
        decrypted_text = self.encryption_obj.decrypt(ciphertext)
        self.assertEqual(self.plaintext, decrypted_text)

    def test_empty_plaintext(self):
        empty_plaintext = b""
        ciphertext = self.encryption_obj.encrypt(empty_plaintext)
        decrypted_text = self.encryption_obj.decrypt(ciphertext)
        self.assertEqual(empty_plaintext, decrypted_text)

    def test_multiple_encryptions(self):
        plaintext2 = b"Second RSA message"
        ciphertext1 = self.encryption_obj.encrypt(self.plaintext)
        ciphertext2 = self.encryption_obj.encrypt(plaintext2)

        decrypted_text1 = self.encryption_obj.decrypt(ciphertext1)
        decrypted_text2 = self.encryption_obj.decrypt(ciphertext2)

        self.assertEqual(self.plaintext, decrypted_text1)
        self.assertEqual(plaintext2, decrypted_text2)

    def test_tampered_ciphertext(self):
        ciphertext = self.encryption_obj.encrypt(self.plaintext)
        tampered_ciphertext = ciphertext[:-1] + (b'\x00' if ciphertext[-1] != 0 else b'\x01')

        with self.assertRaises(ValueError):
            self.encryption_obj.decrypt(tampered_ciphertext)

    def test_large_plaintext(self):
        large_plaintext = get_random_bytes(190)
        ciphertext = self.encryption_obj.encrypt(large_plaintext)
        decrypted_text = self.encryption_obj.decrypt(ciphertext)
        self.assertEqual(large_plaintext, decrypted_text)

    def test_plaintext_exceeding_limit(self):
        too_large_plaintext = get_random_bytes(300)
        with self.assertRaises(ValueError):
            self.encryption_obj.encrypt(too_large_plaintext)
