import ast
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
			"user": os.getenv("USER"),
			"password": os.getenv("PASSWORD"),
			"host": os.getenv("HOST"),
			"port": os.getenv("PORT")
		}

		# Initialize and connect to the database
		self.db = PostgresDB(**self.db_config)
		self.db.connect()

	def register_user(self, username, password):
		"""Register a new user."""
		self.db.insert_user(username, password)

	def authenticate_user(self, client_socket, command):
		username = command[1]
		print(f"Authenticating user: {username}")
		password, challenge = self.get_authentication_challenge(username)
		if password and challenge:
			client_socket.send(f"challenge {challenge}".encode('utf-8'))
			response = client_socket.recv(1024).decode('utf-8')
			answer = bytes.fromhex(response.split()[0])
			nonce = bytes.fromhex(response.split()[2])
			if self.verify_authentication_challenge(username, challenge, answer, nonce):
				print("Authentication successful.")
				client_socket.send("Authentication successful".encode('utf-8'))
			else:
				print("Authentication failed.")
				client_socket.send("Authentication failed".encode('utf-8'))
		else:
			print("Authentication failed.")
			client_socket.send("Authentication failed.".encode('utf-8'))

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

	def close(self):
		"""Close the database connection."""
		self.db.close()


class ClientAuth:
	@staticmethod
	def authenticate_user(username, password, client_socket):
		"""Authenticate a user by sending the username and password to the server."""
		command = f"authenticate {username}"
		client_socket.send(command.encode('utf-8'))
		print("Authentication command sent.")

		# Receive challenge from server
		challenge_data = client_socket.recv(1024).decode('utf-8')
		if challenge_data.startswith("challenge"):
			challenge = challenge_data.split()[1]
			print(f"Challenge received: {challenge}")
			# Respond to the challenge (e.g., echoing the challenge for simplicity in testing)
			key = Hashing.Hashing.hash_data(password).encode('utf-8')[:16].ljust(16, b'\0')
			answer, tag, nonce = AES.SymmetricEncryption(key).encrypt(challenge.encode('utf-8'))
			answer = answer.hex()
			tag = tag.hex()
			nonce = nonce.hex()
			response = f"{answer} {tag} {nonce}".encode('utf-8')

			client_socket.send(response)

			# Receive authentication result
			auth_result = client_socket.recv(1024).decode('utf-8')
			print(f"Server response: {auth_result}")
			return auth_result.split()[1] == "successful"
		else:
			print("Failed to receive challenge or invalid response from server.")
			return False
