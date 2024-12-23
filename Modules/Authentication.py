import hashlib

class Authentication:
    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def verify_password(hashed, password):
        return hashed == hashlib.sha256(password.encode()).hexdigest()
