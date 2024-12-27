import json
import socket

import Modules.AES as AES
from Modules import KeyManagement
import Modules.Hashing as Hashing
from Modules.Authentication import ClientAuth

States = {
    "Main": ["Register", "Auth"],
    "Register": ["Main"],
    "Auth": ["Show list of online people", "Main"],
    "Show list of online people": ["Main"]
}
state = "Main"
user = None
connected = False
client_socket = None
def execute(action):
    global user
    global state
    global connected
    global client_socket
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
        username = input("Enter username: ").strip()
        if not username:
            print("Username cannot be empty")
            return
        email = input("Enter email: ").strip()
        if not email:
          print("Email cannot be empty")
          return
        password = input("Enter password: ").strip()
        if not password:
            print("Password cannot be empty")
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
            return
        password = input("Enter password: ").strip()
        if not password:
            print("Password cannot be empty")
            return
        authentication_status = ClientAuth.authenticate_user(username, password, client_socket)
        if authentication_status:
            user = username
            print("Authentication successful.")
            print(f"Welcome {username}")
        else:
            user = None
            state = "Main"
            print("Authentication failed.")

    elif action == "Show list of online people":
        # TODO: implement logic to find connected clients on various threads
        print("list of friends goes here")
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
