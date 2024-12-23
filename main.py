from CyberTools.Modules.AES import SymmetricEncryption
from CyberTools.Modules.Authentication import Authentication
from CyberTools.Modules.RSA import AsymmetricEncryption
from CyberTools.Modules.hashing import Hashing




if __name__ == "__main__":
    # Symmetric Encryption Test `
    symmetric = SymmetricEncryption()
    message = b"Hello, Secure World!"
    ciphertext, tag = symmetric.encrypt(message)
    print("Symmetric Encrypted:", ciphertext)
    print("Decrypted:", symmetric.decrypt(ciphertext, tag))

    # Asymmetric Encryption Test
    asymmetric = AsymmetricEncryption()
    enc_message = asymmetric.encrypt(message)
    print("Asymmetric Encrypted:", enc_message)
    print("Decrypted:", asymmetric.decrypt(enc_message))

    # Hashing Test
    hash_module = Hashing()
    hashed = hash_module.hash_data(message)
    print("Hashed Message:", hashed)

    # Authentication Test
    auth = Authentication()
    stored_password = auth.hash_password("securepassword")
    print("Password Verified:", auth.verify_password(stored_password, "securepassword"))
