import unittest
import hashlib
from Modules.Hashing import hash_data


class TestHashData(unittest.TestCase):
    def test_hash_of_string(self):
        data = b"Hello, SHA256!"
        expected_hash = hashlib.sha256(data).hexdigest()
        result = hash_data(data)
        self.assertEqual(result, expected_hash)

    def test_hash_of_empty_data(self):
        data = b""
        expected_hash = hashlib.sha256(data).hexdigest()
        result = hash_data(data)
        self.assertEqual(result, expected_hash)

    def test_consistency_of_hash(self):
        data = b"Consistency test"
        hash1 = hash_data(data)
        hash2 = hash_data(data)
        self.assertEqual(hash1, hash2)

    def test_different_data_produces_different_hashes(self):
        data1 = b"Data 1"
        data2 = b"Data 2"
        hash1 = hash_data(data1)
        hash2 = hash_data(data2)
        self.assertNotEqual(hash1, hash2)

    def test_large_data(self):
        data = b"a" * 10**6  # 1 million bytes
        expected_hash = hashlib.sha256(data).hexdigest()
        result = hash_data(data)
        self.assertEqual(result, expected_hash)
