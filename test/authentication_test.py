import os
import unittest
from unittest.mock import MagicMock, patch

from Modules.AES import SymmetricEncryption
from CyberServer.Database import PostgresDB
from Modules.Authentication import ServerAuth, ClientAuth


class TestServerAuth(unittest.TestCase):
	def setUp(self):
		self.mock_db = MagicMock(spec=PostgresDB)
		self.server_auth = ServerAuth()
		self.server_auth.db = self.mock_db

	@patch("os.urandom", return_value=b"random_number_16b")
	def test_get_authentication_challenge(self, mock_urandom):
		username = "kareem"
		self.mock_db.get_user_password.return_value = "test_password"

		password, challenge = self.server_auth.get_authentication_challenge(username)

		self.assertEqual(password, "test_password")
		self.assertEqual(challenge, b"random_number_16b")
		self.mock_db.get_user_password.assert_called_with(username)

	def test_verify_authentication_challenge_success(self):
		username = "kareem"
		challenge = b"random_number_16b"
		password = "674552ada3820f7733c110827306af1bd4d2df14a79dd28ced5f41031fc520ad"
		key = password.encode('utf-8')[:16].ljust(16, b'\0')
		self.mock_db.get_user_password.return_value = password

		cipher = SymmetricEncryption(key)
		ciphertext, tag, nonce = cipher.encrypt(challenge)

		result = self.server_auth.verify_authentication_challenge(username, challenge, ciphertext, nonce)
		self.assertTrue(result)
		self.mock_db.get_user_password.assert_called_once_with(username)

	def test_verify_authentication_challenge_failure(self):
		username = "test_user"
		challenge = b"random_number_16b"
		nonce = b"random_nonce_16b"
		key = b"test_password".ljust(16, b'\0')

		# Create a *real* ciphertext using the AES encryption
		cipher = SymmetricEncryption(key)
		ciphertext, tag, nonce = cipher.encrypt(b"Different_Value")  # encrypt a different value

		# Now use the *real* ciphertext in the test
		result = self.server_auth.verify_authentication_challenge(
			username, challenge, ciphertext, nonce
		)

		self.assertFalse(result)

	def test_register_user(self):
		self.server_auth.register_user("user", "password", "email", "public_key", "device_id")
		self.mock_db.insert_user.assert_called_once_with(
			"user", "password", "email", "public_key", "device_id"
		)

	def test_close(self):
		self.server_auth.close()
		self.mock_db.close.assert_called_once()


class TestClientAuth(unittest.TestCase):
	@patch("Modules.AES.SymmetricEncryption")
	def test_authenticate_user_success(self, MockSymmetricEncryption):
		mock_socket = MagicMock()
		mock_socket.recv.side_effect = [
			b"challenge random_number_16b",
			b"authenticated",
		]

		key = b"password".ljust(16, b'\0')
		mock_cipher = MockSymmetricEncryption.return_value
		mock_cipher.encrypt.return_value = (b"encrypted_answer", b"tag", b"nonce")

		result = ClientAuth.authenticate_user("user", "password", mock_socket)
		self.assertEqual(result, "authenticated")

		mock_socket.send.assert_called()
		mock_socket.recv.assert_called()

	@patch("os.path.exists", return_value=False)
	@patch("builtins.open", create=True)
	@patch("uuid.getnode", return_value=1234567890)
	@patch("os.urandom", return_value=b"random_bytes")
	def test_get_device_identifier(self, mock_urandom, mock_getnode, mock_open, mock_exists):
		with patch("Modules.Hashing.hash_data", return_value="hashed_device_id"):
			result = ClientAuth.get_device_identifier()
			self.assertEqual(result, "hashed_device_id")

			mock_open.assert_called_once_with("this_device_id", "w")
			mock_open.return_value.write.assert_called_once_with("hashed_device_id")
