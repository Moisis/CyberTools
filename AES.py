from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class SymmetricEncryption:
    def __init__(self):
        self.key = get_random_bytes(16)  # AES key
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def encrypt(self, plaintext):
        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag

    def decrypt(self, ciphertext, tag):
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.cipher.nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
