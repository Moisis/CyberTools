import ast
import os

from CyberTools.CyberServer.Database import PostgresDB
from CyberTools.Modules import AES as AES


class ServerAuth:
    def __init__(self):
        # Database credentials
        self.db_config = {
            "db_name": "cybertools",
            "user": "postgres",
            "password": "karim2510",
            "host": "localhost",
            "port": 5432
        }

        # Initialize and connect to the database
        self.db = PostgresDB(**self.db_config)
        self.db.connect()

    def register_user(self, username, password):
        """Register a new user."""
        self.db.insert_user(username, password)

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

        try:
            # Create AES cipher object using the password as the key
            # Ensure the password is exactly 16 bytes (padding or truncating if necessary)
            key = password.encode('utf-8')
            key = key[:16].ljust(16, b'\0')  # Pad or truncate the key to 16 bytes

            # Encrypt the random number
            cipher = AES.SymmetricEncryption(key)  # Using ECB mode for simplicity

            # Return the password, random number, and encrypted random number
            return password, random_number

        except Exception as e:
            print(f"Error during encryption: {e}")
            return None, None, None

    def authenticate_user(self, username, challenge, challenge_response, tag, nonce):
        """
        Authenticate a user by decrypting the challenge response using the user's password as the key.
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
