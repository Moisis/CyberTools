import socket

from CyberTools.CyberServer.ServerAuth import ServerAuth


class ServerAPI:
	def __init__(self, host="127.0.0.1", port=12345):
		"""
		Initialize and start the server.
		:param host: Host address to bind the server (default: 127.0.0.1)
		:param port: Port to listen on (default: 12345)
		"""
		self.host = host
		self.port = port
		self.auth = ServerAuth()

		# Create a socket object
		self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		# Bind the socket to the host and port
		self.server_socket.bind((self.host, self.port))
		print(f"Server started on {self.host}:{self.port}")

		# Start listening for incoming connections
		self.server_socket.listen(5)  # Can handle up to 5 connections in the queue
		print("Waiting for a connection...")

		# Handle incoming connections
		self.handle_connections()

	def handle_connections(self):
		"""Handle incoming client connections."""
		while True:
			try:
				# Accept a new connection
				client_socket, client_address = self.server_socket.accept()
				print(f"Connection established with {client_address}")

				# Receive data from the client
				data = client_socket.recv(1024).decode('utf-8')  # Buffer size is 1024 bytes
				print(f"Received from client: {data}")

				self.handle_user_command(data, client_socket)

				# Close the client connection
				client_socket.close()
				print(f"Connection with {client_address} closed.")

			except Exception as e:
				print(f"An error occurred: {e}")
				break

	def handle_user_command(self, data, client_socket):
		command = data.split()
		if command[0] == "exit":
			self.close_server()
		elif command[0] == "register":
			# Register a new user
			if len(command) == 3:
				username = command[1]
				password = command[2]
				print(f"Registering new user: {username}")
				self.auth.register_user(username, password)
			else:
				print("Invalid command format. Usage: register <username> <password>")
		elif command[0] == "authenticate":
			# Authenticate a user
			if len(command) == 2:
				username = command[1]
				print(f"Authenticating user: {username}")
				password, challenge = self.auth.get_authentication_challenge(username)
				if password and challenge:
					client_socket.send(f"challenge {challenge}".encode('utf-8'))
					response = client_socket.recv(1024).decode('utf-8')
					answer = bytes.fromhex(response.split()[0])
					tag = bytes.fromhex(response.split()[1])
					nonce = bytes.fromhex(response.split()[2])
					if self.auth.authenticate_user(username, challenge, answer, tag, nonce):
						print("Authentication successful.")
						client_socket.send("Authentication successful.".encode('utf-8'))
					else:
						print("Authentication failed.")
						client_socket.send("Authentication failed.".encode('utf-8'))
				else:
					print("Authentication failed.")
					client_socket.send("Authentication failed.".encode('utf-8'))
			else:
				print("Invalid command format. Usage: authenticate <username>")
		else:
			print(f"Command '{command[0]}' not recognized.")

	def close_server(self):
		"""Close the server socket."""
		self.server_socket.close()
		print("Server has been closed.")


try:
	server = ServerAPI()
except KeyboardInterrupt:
	print("\nShutting down the server...")
	server.close_server()
