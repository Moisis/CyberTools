import hashlib
from Crypto.Hash import SHA256


def hash_data(data):
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def hash_sha_256(data):
    h = SHA256.new(data)
    return h
