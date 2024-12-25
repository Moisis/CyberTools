import hashlib


class Hashing:
    @staticmethod
    def hash_data(data):
        hasher = hashlib.sha256()
        hasher.update(data.encode('utf-8'))
        return hasher.hexdigest()
