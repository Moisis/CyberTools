import hashlib


def hash_data(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()
