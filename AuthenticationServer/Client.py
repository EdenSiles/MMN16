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
        with open('me.info', 'r') as f:
            lines = f.readlines()
            if len(lines) >= 2:
                username = lines[0].strip()
                client_id = lines[1].strip()
                return username, client_id
            else:
                print("Invalid format in info.me file")
                return None, None
    except FileNotFoundError:
        print("info.me file not found")
        return None, None
    
    # try:
    #     with open(INFO_ME_FILE, 'r') as f:
    #         username = f.readline().strip()
    #         client_id = f.readline().strip()
    # except FileNotFoundError:
    #     print(f"Error: {INFO_ME_FILE} not found.")
    #     exit(1)
    # return username, client_id

# def read_info_srv():
#     try:
#         with open(INFO_SRV_FILE, 'r') as f:
#             for line in f:
#                 auth_server_ip, auth_server_port = line.strip().split(':')
#            # msg_server_address = f.readline().strip()
#     except FileNotFoundError:
#         print(f"Error: {INFO_SRV_FILE} not found.")
#         exit(1)
#     return auth_server_ip, auth_server_port

def register_to_auth_server(name, password, server_ip, server_port):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
         client_socket.connect((server_ip, server_port))
        # client_socket.connect(('127.0.0.1', 1234))
    except ConnectionRefusedError:
        client_socket.close()
        raise ConnectionRefusedError('Server is not responding. Ensure the server is running and accessible.')

    # Construct the request
    version = 1  # Assuming version is 1
    code = 1024  # Code for registration
    payload = (name + '\x00' + password + '\x00').encode('ascii')
    payload_size = len(payload)
    request = bytearray(16) + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big') + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(1024)

    # Close the connection
    client_socket.close()

    return response.decode()
    
    
    # try:
    #     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     client_socket.connect((AUTH_SERVER_ADDRESS, AUTH_SERVER_PORT))
    #     password_hash = hashlib.sha256(password.encode()).hexdigest()
    #     request = f"REGISTER:{username}:{password_hash}"
    #     client_socket.send(request.encode())
    #     response = client_socket.recv(1024).decode()
    #     if response.startswith("Success"):
    #         print("Registration successful.")
    #         with open(INFO_ME_FILE, 'w') as f:
    #             f.write(f"{username}\n{client_id}")
    #         return client_id
    #     else:
    #         print("Registration failed.")
    #         return None
    # except Exception as e:
    #     print(f"Error registering to authentication server: {e}")
    #     return None

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

def write_user_info_to_file(username):
    client_id = uuid.uuid1().hex
    with open('me.info', 'w') as f:
        f.write(f"{username}\n{client_id}")

def read_info_srv():
    try:
        with open(INFO_SRV_FILE, 'r') as f:
            auth_server_line = f.readline().strip()
            auth_server_ip, auth_server_port = auth_server_line.split(':')
            auth_server_port = int(auth_server_port)  # Convert port to integer
            # Add additional code to read message server info if needed
    except FileNotFoundError:
        print(f"Error: {INFO_SRV_FILE} not found.")
        exit(1)
    except ValueError:
        print("Error: Inva")
    return auth_server_ip, auth_server_port

def parse_response(response):
    # Convert the response to bytes if it's a string
    if isinstance(response, str):
        response = response.encode()

    # Parsing the response into its components
    version = response[0]
    response_code = int.from_bytes(response[1:3], 'big')
    payload_size = int.from_bytes(response[3:7], 'big')
    client_id = response[7:7+payload_size].decode().rstrip('\x00')
    return version, response_code, client_id

def main():

    username = input("Enter your username: ")
    password = input("Enter your password: ")
    
    write_user_info_to_file(username)

    username1, client_id1 = read_info_me()

    auth_server_ip1, auth_server_port1 = read_info_srv()

    response1 =register_to_auth_server(username1, password, auth_server_ip1, auth_server_port1)

    version, response_code, client_id = parse_response(response1)
#    ''' username, client_id = read_info_me()
#     auth_server_ip, auth_server_port = read_info_srv()'''
#     '''
#     if client_id:
#         encrypted_key, ticket = request_symmetric_key(client_id, msg_server_address)
#         if encrypted_key and ticket:
#             key = decrypt_key(encrypted_key, ticket)
#             if key:
#                 message = input("Enter your message: ")
#                 encrypted_message = encrypt_message(message, key)
#                 if encrypted_message:
#                     send_message_to_server(encrypted_message, key)
#                     '''

if __name__ == "__main__":
    main()