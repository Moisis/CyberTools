import base64
import os

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


from Modules import Hashing


def save_key(filename, key):
    with open(filename, 'wb') as f:
        f.write(key)


def load_key(filename):
    with open(filename, 'rb') as f:
        return f.read()


def generate_rsa_key_pair(email):
    key = RSA.generate(2048)
    # Save the private key with an email identifier
    private_key_filename = f'private_key_{email}.pem'
    save_key(private_key_filename, key.export_key())

    # Save the public key with an email identifier
    public_key_filename = f'public_key_{email}.pem'
    save_key(public_key_filename, key.publickey().export_key())

    return key, key.publickey()


def get_rsa_public_key(email):
    public_key_filename = f'public_key_{email}.pem'
    if os.path.exists(public_key_filename):
        return RSA.import_key(load_key(public_key_filename))
    else:
        # Generate a new key pair if the key does not exist
        return generate_rsa_key_pair(email)[1]


def get_rsa_private_key(email):
    private_key_filename = f'private_key_{email}.pem'
    if os.path.exists(private_key_filename):
        return RSA.import_key(load_key(private_key_filename))
    else:
        # Generate a new key pair if the key does not exist
        return generate_rsa_key_pair(email)[0]


def double_encrypt(data: bytes, private_key_sender: RSA.RsaKey, public_key_receiver: RSA.RsaKey) -> str:
    # Sign data first
    # h = SHA256.new(data)
    h = Hashing.hash_sha_256(data)
    signature = pkcs1_15.new(private_key_sender).sign(h)

    # Combine signature and data
    data_with_signature = signature + data

    # Encrypt with receiver's public key
    cipher = PKCS1_OAEP.new(public_key_receiver)
    max_chunk_size = 190  # Safe size for 2048-bit key

    encrypted_chunks = []
    for i in range(0, len(data_with_signature), max_chunk_size):
        chunk = data_with_signature[i:i + max_chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)

    combined = b''.join(encrypted_chunks)
    return base64.b64encode(combined).decode('utf-8')


def double_decrypt(encrypted_data: str, private_key_receiver: RSA.RsaKey, public_key_sender: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(private_key_receiver)
    encrypted_bytes = base64.b64decode(encrypted_data)

    chunk_size = 256  # For 2048-bit key
    decrypted_chunks = []

    for i in range(0, len(encrypted_bytes), chunk_size):
        chunk = encrypted_bytes[i:i + chunk_size]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)

    # Combine decrypted data
    decrypted_data = b''.join(decrypted_chunks)

    # Extract signature and verify
    signature = decrypted_data[:256]  # First 256 bytes for 2048-bit key
    original_data = decrypted_data[256:]

    # h = SHA256.new(original_data)
    h = Hashing.hash_sha_256(original_data)
    try:
        pkcs1_15.new(public_key_sender).verify(h, signature)
        return original_data
    except (ValueError, TypeError):
        raise ValueError("Signature verification failed")

def generate_symmetric_session_key():
    return os.urandom(16)
