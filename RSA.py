from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class AsymmetricEncryption:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()

    def encrypt(self, plaintext):
        cipher = PKCS1_OAEP.new(self.public_key)
        return cipher.encrypt(plaintext)

    def decrypt(self, ciphertext):
        cipher = PKCS1_OAEP.new(self.key)
        return cipher.decrypt(ciphertext)
