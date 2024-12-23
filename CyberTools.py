import socket

import CyberTools.Modules.AES as AES
from CyberTools.Modules import hashing

States = {
	"Main": ["Register", "Auth"],
	"Register": ["Main"],
	"Auth": ["Symmetric Encryption", "Main"],
	"Symmetric Encryption": ["Main"]
}
state = "Main"


def execute(action):
	server_host = "127.0.0.1"  # Server host
	server_port = 12345  # Server port

	# Connect to the server
	try:
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((server_host, server_port))
		print("Connected to the server.")
	except Exception as e:
		print(f"Failed to connect to the server: {e}")
		return

	if action == "Register":
		# Implement Register
		username = input("Enter username: ")
		password = input("Enter password: ")
		password = hashing.Hashing.hash_data(password)
		command = f"register {username} {password}"
		client_socket.send(command.encode('utf-8'))
		print("Registration command sent.")

	elif action == "Auth":
		# Implement Auth
		username = input("Enter username: ")
		password = input("Enter password: ")
		command = f"authenticate {username}"
		client_socket.send(command.encode('utf-8'))
		print("Authentication command sent.")

		# Receive challenge from server
		challenge_data = client_socket.recv(1024).decode('utf-8')
		if challenge_data.startswith("challenge"):
			challenge = challenge_data.split()[1]
			print(f"Challenge received: {challenge}")
			# Respond to the challenge (e.g., echoing the challenge for simplicity in testing)
			key = hashing.Hashing.hash_data(password).encode('utf-8')[:16].ljust(16, b'\0')
			answer, tag, nonce = AES.SymmetricEncryption(key).encrypt(challenge.encode('utf-8'))
			answer = answer.hex()
			tag = tag.hex()
			nonce = nonce.hex()
			response = f"{answer} {tag} {nonce}".encode('utf-8')

			client_socket.send(response)

			# Receive authentication result
			auth_result = client_socket.recv(1024).decode('utf-8')
			print(f"Server response: {auth_result}")
		else:
			print("Failed to receive challenge or invalid response from server.")

	elif action == "Symmetric Encryption":
		# Implement Symmetric Encryption
		module = AES.SymmetricEncryption()
		messages = get_messages()
		for message in messages:
			ciphertext, tag, nonce = module.encrypt(message.encode())
			print(f"Encrypted message: {ciphertext.hex()}")
			print(f"Tag: {tag.hex()}")
			plaintext = module.decrypt(ciphertext, tag)
			print(f"Decrypted message: {plaintext.decode()}")
	else:
		print("Invalid state.")
		return

	print("Press Enter to continue...")
	input()


def get_messages():
	messages = []
	while True:
		new_message = input("Enter a message (type 'q' to finish): ")
		if new_message != "q":
			messages.append(new_message)
		else:
			break
	return messages


print("Welcome to CyberTools!")
print("Please select a tool to use:")
while True:
	print("Current State: " + state)
	for index, state_name in enumerate(States[state]):
		print(f"{index + 1}: {state_name}")
	print("0: Exit")
	selection = input("Selection: ")

	if selection == "0":
		break
	try:
		selection = int(selection)
		if selection < 0 or selection > len(States[state]):
			raise ValueError
	except ValueError:
		print("Invalid selection.")
		continue
	state = States[state][selection - 1]
	execute(state)
