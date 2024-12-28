import json
import socket
import threading
import time

from Crypto.PublicKey import RSA

import Modules.AES as AES
from Modules import KeyManagement
import Modules.Hashing as Hashing
from Modules.Authentication import ClientAuth

#
# class MessageListener(threading.Thread):
#     def __init__(self, client_socket, session_key):
#         super().__init__()
#         self.client_socket = client_socket
#         self.session_key = session_key
#         self.chat_active = False
#         self.chat_session_key = None
#         self.daemon = True  # Thread will exit when main program exits
#
#     def run(self):
#         while True:
#             try:
#                 print("Waiting for messages...")
#                 # make a non blocking call to receive messages
#                 data = self.client_socket.recv(4096).decode('utf-8')
#                 print('received data:', data)
#                 if not data:
#                     # sleep for 2 seconds before trying again
#                     print('sleeping for 2 seconds')
#                     time.sleep(2)
#                     print('waking up')
#                 else:
#                     # print(f"Received: {data}")
#                     with open('debug.txt', 'w') as file:
#                         file.write(data)
#                     try:
#                         # Try to parse as JSON first
#                         message = json.loads(data)
#                         print(f"Message: {message}")
#                         if message.get("action") == "receive_chat":
#                             print('calling handle_incoming_chat')
#                             self.handle_incoming_chat(message)
#                     except json.JSONDecodeError:
#                         print('the error is' + str(json.JSONDecodeError))
#                         # If it's not JSON, it might be encrypted chat data
#                         if self.chat_active:
#                             self.handle_chat_message(data)
#             except Exception as e:
#                 print(f"Error in message listener: {e}")
#                 break
#
#     def handle_incoming_chat(self, message):
#         print(f"\nIncoming chat request from {message['from']}")
#         choice = input("Accept chat? (y/n): ")
#
#         if choice.lower() == 'y':
#             # Decrypt the chat session key
#             encrypted_chat_session_key = message["chat_session_key"]
#             initiator_public_key = message["initiator_public_key"]
#
#             self.chat_session_key = KeyManagement.double_decrypt(
#                 encrypted_chat_session_key,
#                 KeyManagement.get_rsa_private_key(f'{user}@gmail.com'),
#                 RSA.import_key(initiator_public_key)
#             )
#
#             # Send acceptance
#             self.client_socket.send(json.dumps({
#                 "action": "chat_accepted",
#                 "to": message["from"]
#             }).encode('utf-8'))
#
#             self.chat_active = True
#             self.start_chat()
#         else:
#             self.client_socket.send(json.dumps({
#                 "action": "chat_rejected",
#                 "to": message["from"]
#             }).encode('utf-8'))
#
#     def handle_chat_message(self, encrypted_message):
#         if encrypted_message == ":q":
#             print("\nChat ended by other party")
#             self.chat_active = False
#             return
#
#         # Here you would decrypt the message using chat_session_key
#         print(f"\nThem: {encrypted_message}")
#         print("You: ", end='', flush=True)
#
#     def start_chat(self):
#         def send_messages():
#             while self.chat_active:
#                 try:
#                     message = input("You: ")
#                     if message == ":q":
#                         self.chat_active = False
#                         self.client_socket.send(":q".encode('utf-8'))
#                         break
#                     # Here you would encrypt the message using chat_session_key
#                     self.client_socket.send(message.encode('utf-8'))
#                 except Exception as e:
#                     print(f"Error sending message: {e}")
#                     break
#
#         # Start sending thread
#         send_thread = threading.Thread(target=send_messages)
#         send_thread.daemon = True
#         send_thread.start()
#

States = {
    "Main": ["Register", "Auth"],
    "Register": ["Main"],
    "Auth": ["Upload Text", "Pull Texts", "Main"],
    "Upload Text": ["Upload Text", "Pull Texts", "Main"],
    "Pull Texts": ["Upload Text", "Pull Texts", "Main"]
}
state = "Main"
user = None
connected = False
client_socket = None
session_key_with_server = None


def upload_text():
    if not user or not session_key_with_server:
        print("Please authenticate first")
        return

    recipient = input("Enter recipient username: ").strip()
    if not recipient:
        print("Recipient cannot be empty")
        return

    # Request recipient's public key from server
    command_data = {
        "action": "get_public_key",
        "username": recipient
    }
    client_socket.send(json.dumps(command_data).encode('utf-8'))

    # Receive encrypted public key
    encrypted_data = client_socket.recv(1024).decode('utf-8')
    encrypted_key, tag, nonce = encrypted_data.split()
    encrypted_key = bytes.fromhex(encrypted_key)
    tag = bytes.fromhex(tag)
    nonce = bytes.fromhex(nonce)

    # Decrypt using session key
    recipient_public_key = AES.SymmetricEncryption(session_key_with_server).decrypt(encrypted_key, tag, nonce)

    # Get text from user
    title = input("Enter text title: ").strip()
    content = input("Enter text content: ").strip()

    # Generate AES key for text encryption
    text_key = AES.SymmetricEncryption().key

    # Encrypt text
    encrypted_text, tag, nonce = AES.SymmetricEncryption(text_key).encrypt(content.encode('utf-8'))

    # Hash original text
    text_hash = Hashing.hash_data(content.encode('utf-8'))

    # Encrypt and sign the AES key
    recipient_public_key_obj = RSA.import_key(recipient_public_key)
    sender_private_key = KeyManagement.get_rsa_private_key(f'{user}@gmail.com')
    encrypted_key = KeyManagement.double_encrypt(text_key, sender_private_key, recipient_public_key_obj)

    # Send to server
    command_data = {
        "action": "upload_text",
        "recipient": recipient,
        "title": title,
        "encrypted_text": encrypted_text.hex(),
        "text_hash": text_hash,
        "encrypted_key": encrypted_key,
        "tag": tag.hex(),
        "nonce": nonce.hex()
    }
    client_socket.send(json.dumps(command_data).encode('utf-8'))

    response = client_socket.recv(1024).decode('utf-8')
    print(response)


def pull_texts():
    if not user or not session_key_with_server:
        print("Please authenticate first")
        return

    # Request list of texts
    command_data = {
        "action": "get_texts"
    }
    client_socket.send(json.dumps(command_data).encode('utf-8'))

    # Receive list of texts
    response = client_socket.recv(8192).decode('utf-8')
    texts = json.loads(response)

    if not texts:
        print("No texts available")
        return

    print("\nAvailable texts:")
    for i, text in enumerate(texts):
        print(f"{i + 1}: {text['title']} (from: {text['sender']})")

    choice = input("\nEnter number to read (or 0 to cancel): ")
    if choice == "0" or not choice.isdigit() or int(choice) > len(texts):
        return

    selected = texts[int(choice) - 1]

    # Request specific text
    command_data = {
        "action": "get_text_content",
        "text_id": selected["id"]
    }
    client_socket.send(json.dumps(command_data).encode('utf-8'))

    # Receive encrypted text
    response = json.loads(client_socket.recv(4096).decode('utf-8'))

    # Decrypt the symmetric key using private key
    encrypted_key = response["encrypted_key"]
    sender_public_key = RSA.import_key(response["sender_public_key"])
    receiver_private_key = KeyManagement.get_rsa_private_key(f'{user}@gmail.com')

    symmetric_key = KeyManagement.double_decrypt(
        encrypted_key,
        receiver_private_key,
        sender_public_key
    )

    # Decrypt the text
    encrypted_text = bytes.fromhex(response["encrypted_text"])
    tag = bytes.fromhex(response["tag"])
    nonce = bytes.fromhex(response["nonce"])

    decrypted_text = AES.SymmetricEncryption(symmetric_key).decrypt(encrypted_text, tag, nonce)

    # Verify hash
    calculated_hash = Hashing.hash_data(decrypted_text)
    if calculated_hash != response["text_hash"]:
        print("Warning: Text integrity check failed!")
        return

    print(f"\nTitle: {selected['title']}")
    print(f"From: {selected['sender']}")
    print(f"Content: {decrypted_text.decode('utf-8')}")
def execute(action):
    global user
    global state
    global connected
    global client_socket
    global session_key_with_server
    server_host = "127.0.0.1"  # Server host
    server_port = 12345  # Server port

    # Connect to the server
    try:
        if not connected:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_host, server_port))
            print("Connected to the server.")
            connected = True
    except Exception as e:
        print(f"Failed to connect to the server: {e}")
        return

    if action == "Register":
        # Implement Register
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty")
            state = "Main"
            return
        email = input("Enter email: ").strip()
        if not email:
            print("Email cannot be empty")
            state = "Main"
            return
        password = input("Enter password: ").strip()
        if not password:
            print("Password cannot be empty")
            state = "Main"
            return
        password = Hashing.hash_data(password.encode('utf-8'))
        public_key = KeyManagement.get_rsa_public_key(email).export_key().decode('utf-8')
        device_id = ClientAuth.get_device_identifier()

        command_data = {
            "action": "register",
            "username": username,
            "password": password,
            "email": email,
            "public_key": public_key,
            "device_id": device_id
        }

        command = json.dumps(command_data)
        client_socket.send(command.encode('utf-8'))

        # receive your key concatenated with random number then hashed
        public_key_hashed_with_code_from_server = client_socket.recv(1024).decode('utf-8')
        public_key_hashed_with_code_from_server = json.loads(public_key_hashed_with_code_from_server)['public_key_hash']
        # enter the code you received on your email
        code = input("Enter the code you received on your email: ")

        # add the code to the start of your public key and hash it
        public_key_with_code_local = code + public_key
        public_key_with_code_local_hashed = Hashing.hash_data(public_key_with_code_local.encode('utf-8'))

        if public_key_hashed_with_code_from_server == public_key_with_code_local_hashed:
            # send the code to the server encrypted with your private key and the server public key
            server_public_key = KeyManagement.get_rsa_public_key('server@secure.org')
            private_key = KeyManagement.get_rsa_private_key(email)
            encrypted_code = KeyManagement.double_encrypt(code.encode('utf-8'), private_key, server_public_key)
            client_socket.send(encrypted_code.encode('utf-8'))
            print("Registration successful.")
        else:
            print("Your connection is not secure. Try again from another network.")

        print("Registration command sent.")

    elif action == "Auth":
        # Implement Auth
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty")
            state = "Main"
            return
        password = input("Enter password: ").strip()
        if not password:
            print("Password cannot be empty")
            state = "Main"
            return
        authentication_status = ClientAuth.authenticate_user(username, password, client_socket)
        if authentication_status != "failed":
            session_key = KeyManagement.double_decrypt(authentication_status,
                                                       KeyManagement.get_rsa_private_key(f'{username}@gmail.com'),
                                                       KeyManagement.get_rsa_public_key('server@secure.org'))
            session_key_with_server = session_key
            print('session key with server:', session_key_with_server)
            user = username
            print("Authentication successful.")
            print(f"Welcome {username}")
        else:
            user = None
            state = "Main"
            print("Authentication failed.")

    elif action == "Show list of online people":
        command_data = {
            "action": "list",
        }
        client_socket.send(json.dumps(command_data).encode('utf-8'))
        print(client_socket.recv(1024).decode('utf-8'))
    elif action == "Back":
        state = "Auth"
    elif action == "Upload Text":
        upload_text()
    elif action == "Pull Texts":
        pull_texts()
    elif action == "Exit":
        command_data = {
            "action": "exit",
        }
        client_socket.send(json.dumps(command_data).encode('utf-8'))
        return
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
        execute("Exit")
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
