import json
import socket
import string
from secrets import choice

import threading
from Crypto.PublicKey import RSA

from CyberServer import EmailSender
from Modules import Hashing, KeyManagement, AES
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
        self.clients = {}
        self.client_session_keys = {}
        self.db = self.auth.db
        self.init_texts_table()
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
            # self.handle_connections()
        except socket.error as e:
            print(f"socket error during init: {e}")

    def init_texts_table(self):
        """Initialize the texts table in PostgreSQL."""
        try:
            print('initializing texts table')
            create_table_query = """
               CREATE TABLE IF NOT EXISTS texts (
                   id SERIAL PRIMARY KEY,
                   sender VARCHAR(255) NOT NULL,
                   recipient VARCHAR(255) NOT NULL,
                   title VARCHAR(255) NOT NULL,
                   encrypted_text TEXT NOT NULL,
                   text_hash TEXT NOT NULL,
                   encrypted_key TEXT NOT NULL,
                   tag TEXT NOT NULL,
                   nonce TEXT NOT NULL,
                   timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
               );"""
            self.db.cursor.execute(create_table_query)
            self.db.connection.commit()
            print("Texts table initialized successfully.")
        except Exception as e:
            print(f"Error initializing texts table: {e}")

    def handle_client(self, client_socket, client_address):
        """Handle communication with a connected client."""
        print(f"Client {client_address} connected.")
        try:
            while True:
                data = client_socket.recv(8192).decode('utf-8')
                if data:
                    print(f"Received from {client_address}: {data}")
                    self.handle_user_command(data, client_socket)
        except Exception as e:
            print(f"Error with client {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"Connection with {client_address} closed.")

    def handle_user_command(self, data, client_socket):
        command = json.loads(data)
        if command.get("action") == "exit":
            res = dict((v, k) for k, v in self.clients.items())
            del self.clients[res[client_socket]]
            del self.client_session_keys[res[client_socket]]
            print(f"client {res[client_socket]} closed")
        elif command.get("action") == "register":
            self.handle_user_registration(data, client_socket)
        elif command.get("action") == "authenticate":
            user_name = command.get("username")
            # Authenticate a user
            if ServerAuth().authenticate_user(client_socket, user_name):
                print('generating session key')
                # generate a session key
                session_key = AES.SymmetricEncryption().key
                # get the client public key from the database
                client_public_key = self.auth.get_client_public_key(user_name)
                # sign the session key with the server private key then encrypt it with the client public key
                server_private_key = KeyManagement.get_rsa_private_key('server@secure.org')
                client_public_key_obj = RSA.import_key(client_public_key)
                encrypted_session_key = KeyManagement.double_encrypt(session_key, server_private_key,
                                                                     client_public_key_obj)
                # send the encrypted session key to the client
                client_socket.send(encrypted_session_key.encode('utf-8'))
                # add the session key to the clients dictionary
                self.client_session_keys[user_name] = session_key
                self.clients[user_name] = client_socket
                print('session key sent', session_key)
            else:
                print('sending failure message')
                client_socket.send("failed".encode('utf-8'))
        elif command.get("action") == "get_public_key":
            username = command.get("username")
            public_key = self.auth.get_client_public_key(username)
            if public_key:
                # Get requester's username and session key
                requester = dict((v, k) for k, v in self.clients.items())[client_socket]
                session_key = self.client_session_keys[requester]

                # Encrypt public key with session key
                encrypted_key, tag, nonce = AES.SymmetricEncryption(session_key).encrypt(
                    public_key.encode('utf-8')
                )
                response = f"{encrypted_key.hex()} {tag.hex()} {nonce.hex()}"
                client_socket.send(response.encode('utf-8'))
            else:
                client_socket.send("User not found".encode('utf-8'))

        elif command.get("action") == "upload_text":
            print('uploading text to database')
            sender = dict((v, k) for k, v in self.clients.items())[client_socket]
            insert_query = """
                           INSERT INTO texts 
                           (sender, recipient, title, encrypted_text, text_hash, encrypted_key, tag, nonce)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"""

            self.db.cursor.execute(insert_query, (
                sender,
                command["recipient"],
                command["title"],
                command["encrypted_text"],
                command["text_hash"],
                command["encrypted_key"],
                command["tag"],
                command["nonce"]
            ))
            self.db.connection.commit()
            # TODO: Update database with

            client_socket.send("Text uploaded successfully".encode('utf-8'))

        elif command.get("action") == "get_texts":
            recipient = dict((v, k) for k, v in self.clients.items())[client_socket]
            fetch_query = """
                            SELECT id, sender, title 
                            FROM texts 
                            WHERE recipient = %s 
                            ORDER BY timestamp DESC;"""

            self.db.cursor.execute(fetch_query, (recipient,))
            texts = [{"id": row[0], "sender": row[1], "title": row[2]}
                     for row in self.db.cursor.fetchall()]

            # TODO: fetch texts from database
            client_socket.send(json.dumps(texts).encode('utf-8'))

        elif command.get("action") == "get_text_content":
            recipient = dict((v, k) for k, v in self.clients.items())[client_socket]
            text_id = command["text_id"]
            fetch_query = """
                            SELECT * FROM texts 
                            WHERE id = %s AND recipient = %s;"""
            self.db.cursor.execute(fetch_query, (text_id, recipient))
            text = self.db.cursor.fetchone()
            if text:
                sender_public_key = self.auth.get_client_public_key(text[1])  # text[1] is sender
                response = {
                    "encrypted_text": text[4],  # encrypted_text
                    "text_hash": text[5],  # text_hash
                    "encrypted_key": text[6],  # encrypted_key
                    "tag": text[7],  # tag
                    "nonce": text[8],  # nonce
                    "sender_public_key": sender_public_key
                }
            # TODO: fetch text from database

            if text:
                sender_public_key = self.auth.get_client_public_key(text[1])  # text[1] is sender
                response = {
                    "encrypted_text": text[4],  # encrypted_text
                    "text_hash": text[5],  # text_hash
                    "encrypted_key": text[6],  # encrypted_key
                    "tag": text[7],  # tag
                    "nonce": text[8],  # nonce
                    "sender_public_key": sender_public_key
                }
                client_socket.send(json.dumps(response).encode('utf-8'))
            else:
                client_socket.send("Text not found".encode('utf-8'))

        # elif command.get("action") == "chat":
        #     receiver = command.get("username")
        #     initiator = dict((v, k) for k, v in self.clients.items())[client_socket]
        #
        #     if receiver not in self.clients:
        #         client_socket.send(json.dumps({
        #             "action": "error",
        #             "message": "User is offline"
        #         }).encode('utf-8'))
        #         return
        #
        #     # Get and encrypt receiver's public key
        #     receiver_public_key = self.auth.get_client_public_key(receiver)
        #     initiator_session_key = self.client_session_keys[initiator]
        #
        #     encrypted_receiver_public_key, tag, nonce = AES.SymmetricEncryption(initiator_session_key).encrypt(
        #         receiver_public_key.encode('utf-8')
        #     )
        #
        #     print('sending encrypted public key to initiator')
        #     # Send encrypted public key to initiator
        #     client_socket.send(f"{encrypted_receiver_public_key.hex()} {tag.hex()} {nonce.hex()}".encode('utf-8'))
        #
        #     # Receive chat session key from initiator
        #     encrypted_chat_session_key = client_socket.recv(1024).decode('utf-8')
        #     print('received encrypted chat session key from initiator')
        #     # Send chat request to receiver
        #     print('sending chat request to receiver')
        #     receiver_socket = self.clients[receiver]
        #     initiator_public_key = self.auth.get_client_public_key(initiator)
        #     # stop the receiver thread and handle it here
        #     chat_request = {
        #         "action": "receive_chat",
        #         "from": initiator,
        #         "chat_session_key": encrypted_chat_session_key,
        #         "initiator_public_key": initiator_public_key
        #     }
        #
        #     receiver_socket.send(json.dumps(chat_request).encode('utf-8'))
        #
        #     # Wait for receiver's response
        #     response = receiver_socket.recv(1024).decode('utf-8')
        #     print('received response from receiver at server', response)
        #     response_data = json.loads(response)
        #
        #     # Forward response to initiator
        #     client_socket.send(response.encode('utf-8'))
        #
        #     if response_data.get("action") == "chat_accepted":
        #         self.handle_chat_relay(client_socket, receiver_socket, initiator, receiver)
        #
        # elif command.get("action") == "list":
        #     clients_list = []
        #     for key, value in self.clients.items():
        #         if value != client_socket:
        #             clients_list.append(key)
        #     print(clients_list)
        #     print(self.clients)
        #     if clients_list:
        #         client_socket.send('/n'.join(clients_list).encode('utf-8'))
        #     else:
        #         client_socket.send('no one is online now, check again later'.encode('utf-8'))
        else:
            print(f"Command '{command[0]}' not recognized.")

    # def handle_chat_relay(self, socket1, socket2, user1, user2):
    #     def relay_messages(from_socket, to_socket):
    #         try:
    #             while True:
    #                 message = from_socket.recv(1024).decode('utf-8')
    #                 if not message or message == ":q":
    #                     to_socket.send(":q".encode('utf-8'))
    #                     break
    #                 to_socket.send(message.encode('utf-8'))
    #         except Exception as e:
    #             print(f"Error in chat relay: {e}")
    #             try:
    #                 to_socket.send(":q".encode('utf-8'))
    #             except:
    #                 pass
    #
    #     thread1 = threading.Thread(target=relay_messages, args=(socket1, socket2))
    #     thread2 = threading.Thread(target=relay_messages, args=(socket2, socket1))
    #
    #     thread1.daemon = True
    #     thread2.daemon = True
    #
    #     thread1.start()
    #     thread2.start()

    def handle_user_registration(self, data, client_socket):
        """Handle user registration."""
        try:
            command = json.loads(data)
            if command.get("action") == "register":
                username = command["username"]
                password = command["password"]
                email = command["email"]
                client_public_key = command["public_key"]
                device_id = command["device_id"]

                code = self.generate_secure_code()
                EmailSender.send_email(email, code)
                print(f"Registration code sent to {email}")

                # add the code to the start of the public key and hash it
                public_key_with_code = code + client_public_key
                public_key_with_code_hashed = Hashing.hash_data(public_key_with_code.encode('utf-8'))

                # Send the code concatenated with the public key hash to the client
                response = json.dumps({"public_key_hash": public_key_with_code_hashed})
                client_socket.send(response.encode('utf-8'))

                # receive the code from the user
                encrypted_data = client_socket.recv(1024)
                encrypted_data = encrypted_data.decode('utf-8')
                server_private_key = KeyManagement.get_rsa_private_key('server@secure.org')
                client_public_key_obj = RSA.import_key(client_public_key)
                decrypted_data = KeyManagement.double_decrypt(encrypted_data, server_private_key,
                                                              client_public_key_obj)
                decrypted_data = decrypted_data.decode('utf-8')
                print('decrypted code at the server:', decrypted_data)

                if decrypted_data == code:
                    # Register the user
                    self.auth.register_user(username, password, email, client_public_key, device_id)
                    print("User registered successfully.")
                else:
                    print("Registration code mismatch. Registration failed.")
            else:
                print("Invalid command action.")
        except json.JSONDecodeError:
            print("Invalid JSON format received.")

    @staticmethod
    def generate_secure_code(length=8):
        # Define the characters to choose from for better entropy
        characters = string.ascii_letters + string.digits
        # Generate the code by cryptographically secure random selection
        code = ''.join(choice(characters) for _ in range(length))
        return code

    def start(self):
        """Accept and handle multiple client connections."""
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                # save the client thread
                client_thread.start()
        except KeyboardInterrupt:
            print("\nShutting down the server...")
        finally:
            self.close_server()


if __name__ == "__main__":
    server = ServerAPI()
    server.start()
