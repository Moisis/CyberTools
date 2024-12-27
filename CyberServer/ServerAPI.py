import socket

from Modules.Authentication import ServerAuth


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
        self.client_connected = False
        try:
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
        except socket.error as e:
            print(f"socket error during init: {e}")

    def handle_connections(self):
        """Handle incoming client connections."""
        while True:
            try:
                if not self.client_connected:
                    # Accept a new connection
                    client_socket, client_address = self.server_socket.accept()
                    print(f"Connection established with {client_address}")
                    self.client_connected = True

                # Receive data from the client
                data = client_socket.recv(1024).decode('utf-8')  # Buffer size is 1024 bytes
                print(f"Received from client: {data}")

                self.handle_user_command(data, client_socket)

            # Close the client connection
            # client_socket.close()
            # print(f"Connection with {client_address} closed.")

            except Exception as e:
                print(f"An error occurred: {e}")
                break

    def handle_user_command(self, data, client_socket):
        try:
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
                    ServerAuth().authenticate_user(client_socket, command)
                else:
                    print("Invalid command format. Usage: authenticate <username>")
            else:
                print(f"Command '{command[0]}' not recognized.")
        except Exception as e:
            print(f"Error handling command: {e}")
            client_socket.send(b"Error processing command.\n")

    def close_server(self):
        """Close the server socket."""
        self.server_socket.close()
        print("Server has been closed.")


try:
    server = ServerAPI()
except KeyboardInterrupt:
    print("\nShutting down the server...")
    server.close_server()
