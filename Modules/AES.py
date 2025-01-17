from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class SymmetricEncryption:
    def __init__(self, key=None):
        if key:
            self.key = key
        else:
            self.key = get_random_bytes(16)
        self.cipher = AES.new(self.key, AES.MODE_EAX)

    def encrypt(self, plaintext):
        self.cipher = AES.new(self.key, AES.MODE_EAX)  # to make new nonce
        print(self.cipher.nonce)
        ciphertext, tag = self.cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, self.cipher.nonce

    def decrypt(self, ciphertext, tag=None, nonce=None):
        if nonce:
            self.cipher.nonce = nonce
        cipher = AES.new(self.key, AES.MODE_EAX, nonce=self.cipher.nonce)
        if tag:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            plaintext = cipher.decrypt(ciphertext)
        return plaintext
