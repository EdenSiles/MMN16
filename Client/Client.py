# client.py

import socket
import base64
import uuid
import hashlib
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Constants
AUTH_SERVER_ADDRESS = "127.0.0.1"
AUTH_SERVER_PORT = 1234
MSG_SERVER_ADDRESS = "127.0.0.1"
MSG_SERVER_PORT = 1235
INFO_ME_FILE = "me.info"
INFO_SRV_FILE = "srv.info"
PROTOCOL_VERSION = 24

def read_info_me():
    try:
        with open(INFO_ME_FILE, 'r') as f:
            username = f.readline().strip()
            client_id = f.readline().strip()
    except FileNotFoundError:
        print(f"Error: {INFO_ME_FILE} not found.")
        exit(1)
    return username, client_id

def read_info_srv():
    try:
        with open(INFO_SRV_FILE, 'r') as f:
            for line in f:
                auth_server_ip, auth_server_port = line.strip().split(':')
           # msg_server_address = f.readline().strip()
    except FileNotFoundError:
        print(f"Error: {INFO_SRV_FILE} not found.")
        exit(1)
    return auth_server_ip, auth_server_port

def register_to_auth_server(username, password):
    try:
        client_id = uuid.uuid1().hex
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((AUTH_SERVER_ADDRESS, AUTH_SERVER_PORT))
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        request = f"REGISTER:{username}:{password_hash}"
        client_socket.send(request.encode())
        response = client_socket.recv(1024).decode()
        if response.startswith("Success"):
            print("Registration successful.")
            with open(INFO_ME_FILE, 'w') as f:
                f.write(f"{username}\n{client_id}")
            return client_id
        else:
            print("Registration failed.")
            return None
    except Exception as e:
        print(f"Error registering to authentication server: {e}")
        return None

def request_symmetric_key(client_id, server_id):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((AUTH_SERVER_ADDRESS, AUTH_SERVER_PORT))
        request = f"KEY_REQUEST:{client_id}:{server_id}"
        client_socket.send(request.encode())
        response = client_socket.recv(1024).decode()
        encrypted_key, ticket = response.split(':')
        return encrypted_key, ticket
    except Exception as e:
        print(f"Error requesting symmetric key: {e}")
        return None, None

def decrypt_key(encrypted_key, encrypted_ticket):
    try:
        with open(INFO_ME_FILE, 'r') as f:
            password = f.readline().strip()
        password_hash = hashlib.sha256(password.encode()).digest()
        key = PBKDF2(password_hash, base64.b64decode(encrypted_ticket)[:16], dkLen=32)
        cipher = AES.new(key, AES.MODE_EAX, base64.b64decode(encrypted_ticket)[:16])
        key = cipher.decrypt(base64.b64decode(encrypted_key)).decode()
        return key
    except Exception as e:
        print(f"Error decrypting key: {e}")
        return None

def encrypt_message(message, key):
    try:
        aes_key = base64.b64decode(key)
        cipher = AES.new(aes_key, AES.MODE_EAX)
        encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
        return base64.b64encode(encrypted_message).decode()
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None

def send_message_to_server(encrypted_message, key):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((MSG_SERVER_ADDRESS, MSG_SERVER_PORT))
        request = f"SEND_MESSAGE:{encrypted_message}:{key}"
        client_socket.send(request.encode())
        response = client_socket.recv(1024).decode()
        if response == "Message received":
            print("Message sent successfully.")
        else:
            print("Error sending message.")
    except Exception as e:
        print(f"Error sending message: {e}")

def main():
    username, client_id = read_info_me()
    auth_server_ip, auth_server_port = read_info_srv()

    password = input("Enter your password: ")
    client_id = register_to_auth_server(username, password)
    '''
    if client_id:
        encrypted_key, ticket = request_symmetric_key(client_id, msg_server_address)
        if encrypted_key and ticket:
            key = decrypt_key(encrypted_key, ticket)
            if key:
                message = input("Enter your message: ")
                encrypted_message = encrypt_message(message, key)
                if encrypted_message:
                    send_message_to_server(encrypted_message, key)
                    '''

if __name__ == "__main__":
    main()
