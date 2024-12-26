import socket

import Modules.AES as AES
from Modules.Hashing import Hashing
from Modules.Authentication import ClientAuth

States = {
	"Main": ["Register", "Auth"],
	"Register": ["Main"],
	"Auth": ["Symmetric Encryption", "Main"],
	"Symmetric Encryption": ["Main"]
}
state = "Main"
user = None


def execute(action):
	global user
	global state
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
		password = Hashing.hash_data(password)
		command = f"register {username} {password}"
		client_socket.send(command.encode('utf-8'))
		print("Registration command sent.")

	elif action == "Auth":
		# Implement Auth
		username = input("Enter username: ")
		password = input("Enter password: ")
		authentication_status = ClientAuth.authenticate_user(username, password, client_socket)
		if authentication_status:
			user = username
			print("Authentication successful.")
			print(f"Welcome {username}")
		else:
			user = None
			state = "Main"
			print("Authentication failed.")

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
	if state == "Main":
		state = "Main"
		continue
	execute(state)
