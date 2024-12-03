import hashlib

class Hashing:
    @staticmethod
    def hash_data(data):
        hasher = hashlib.sha256()
        hasher.update(data)
        return hasher.hexdigest()
