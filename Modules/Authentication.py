import ast
import json
import uuid

from dotenv import load_dotenv
import os

from CyberServer.Database import PostgresDB
import Modules.AES as AES
import Modules.Hashing as Hashing


class ServerAuth:
	def __init__(self):
		# Load environment variables
		load_dotenv("../.env")
		# Database credentials
		self.db_config = {
			"db_name": os.getenv("DB_NAME"),
			"user": os.getenv("DB_USER"),
			"password": os.getenv("DB_PASSWORD"),
			"host": os.getenv("DB_HOST"),
			"port": os.getenv("DB_PORT")
		}

		# Initialize and connect to the database
		self.db = PostgresDB(**self.db_config)
		self.db.connect()

	def register_user(self, username, password, email, public_key, device_id):
		"""Register a new user."""
		self.db.insert_user(username, password, email, public_key, device_id)

	def authenticate_user(self, client_socket, user_name):
		print(f"Authenticating user: {user_name}")
		password, challenge = self.get_authentication_challenge(user_name)
		if password and challenge:
			client_socket.send(f"challenge {challenge}".encode('utf-8'))
			response = client_socket.recv(1024).decode('utf-8')
			answer = bytes.fromhex(response.split()[0])
			nonce = bytes.fromhex(response.split()[2])
			if self.verify_authentication_challenge(user_name, challenge, answer, nonce):
				print("Authentication successful.")
				return True
			else:
				print("Authentication failed.")
				return False
		else:
			print("Authentication failed.")
			return False

	def get_authentication_challenge(self, username):
		"""
		Authenticate a user by generating a random number, encrypting it with their password as the key,
		and returning the password, original random number, and encrypted random number.
		:param username: Username of the user
		:return: Tuple (password, random_number, encrypted_random) or None if user not found
		"""
		# Get the user's password from the database
		password = self.db.get_user_password(username)
		if password is None:
			print("User not found.")
			return None, None, None

		# Generate a random number
		random_number = os.urandom(16)  # Generate a secure random 16-byte number
		return password, random_number

	def verify_authentication_challenge(self, username, challenge, challenge_response, nonce):
		"""
		Authenticate a user by decrypting the challenge response using the user's password as the key.
		:param nonce: the nonce used for encryption
		:param username: Username of the user
		:param challenge: Original challenge sent to the user
		:param challenge_response: Encrypted challenge response from the user
		:return: True if the challenge response matches the original challenge, False otherwise
		"""
		# Get the user's password from the database
		password = self.db.get_user_password(username)
		if password is None:
			print("User not found.")
			return False

		try:
			# Create AES cipher object using the password as the key
			# Ensure the password is exactly 16 bytes (padding or truncating if necessary)
			key = password.encode('utf-8')
			key = key[:16].ljust(16, b'\0')  # Pad or truncate the key to 16 bytes

			# Decrypt the challenge response
			cipher = AES.SymmetricEncryption(key)  # Using ECB mode for simplicity
			decrypted_challenge = cipher.decrypt(challenge_response, nonce=nonce)
			decrypted_challenge = ast.literal_eval(decrypted_challenge.decode('utf-8'))
			return challenge == decrypted_challenge

		except Exception as e:
			print(f"Error during decryption: {e}")
			return False

	def get_client_public_key(self, username):
		"""Get the public key of a client from the database."""
		return self.db.get_client_public_key(username)

	def close(self):
		"""Close the database connection."""
		self.db.close()


class ClientAuth:
	@staticmethod
	def authenticate_user(username, password, client_socket) -> str:
		"""
		Authenticate a user by sending the username and password to the server.

		:returns symmetric key if authentication is successful, "failed" otherwise
		"""

		command_data = {
			"action": "authenticate",
			"username": username
		}
		command = json.dumps(command_data)
		client_socket.send(command.encode('utf-8'))
		print("Authentication command sent.")

		# Receive challenge from server
		challenge_data = client_socket.recv(1024).decode('utf-8')
		if challenge_data.startswith("challenge"):
			challenge = challenge_data.split()[1]
			print(f"Challenge received: {challenge}")
			# Respond to the challenge (e.g., echoing the challenge for simplicity in testing)
			key = Hashing.hash_data(password.encode('utf-8')).encode('utf-8')[:16].ljust(16, b'\0')
			answer, tag, nonce = AES.SymmetricEncryption(key).encrypt(challenge.encode('utf-8'))
			answer = answer.hex()
			tag = tag.hex()
			nonce = nonce.hex()
			response = f"{answer} {tag} {nonce}".encode('utf-8')

			client_socket.send(response)

			# Receive authentication result
			auth_result = client_socket.recv(1024).decode('utf-8')
			print(f"Server response: {auth_result}")
			return auth_result
		else:
			print("Failed to receive challenge or invalid response from server.")
			return "failed"

	@staticmethod
	def get_device_identifier():
		"""Generate a unique identifier for the device using mac address with a random number and save it
		to file this_device_id."""

		if not os.path.exists("this_device_id"):
			# generate a unique identifier for the device using mac address and a random number
			mac_address = uuid.getnode()
			random_number = os.urandom(8).hex()
			device_id = f"{mac_address}_{random_number}"
			# hash the device_id
			hashed_device_id = Hashing.hash_data(device_id.encode('utf-8'))
			with open("this_device_id", "w") as f:
				f.write(hashed_device_id)
		else:
			with open("this_device_id", "r") as f:
				hashed_device_id = f.read()
		return hashed_device_id
