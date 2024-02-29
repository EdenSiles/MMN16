import socket
import threading
import time
from ClientManager import *
from EncryptionUtils import decrypt_key
from Tools import *

# Read server details from 'info.msg' file
try:
    with open('info.msg', 'r') as file:
        server_details = file.read().splitlines()
        MSG_SERVER_IP = server_details[0].split(':')[0]
        MSG_SERVER_PORT = int(server_details[0].split(':')[1])
        MSG_SERVER_NAME = server_details[1]
        MSG_SERVER_IDENTIFIER = server_details[2]
        MSG_SERVER_ENCRYPTION = server_details[3]
except FileNotFoundError:
    print("Warning: 'info.msg' file not found. Default server details will be used.")
    # Default details (These should be replaced with actual default values)
    MSG_SERVER_IP = '127.0.0.1'
    MSG_SERVER_PORT = 1235
    MSG_SERVER_NAME = 'Printer 20'
    MSG_SERVER_IDENTIFIER = '64f3f63985f04beb81a0e43321880182'
    MSG_SERVER_ENCRYPTION = 'x/wTp6+VCpH3hnSo0Ha46Q=='





class MessageServer:
    def __init__(self):
        self.client_manager = ClientManager()
    
    def start_server(self):
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to the server IP and port from ServerConfig
        server_socket.bind((MSG_SERVER_IP, MSG_SERVER_PORT))

        # Start listening for client connections
        server_socket.listen(5)
        print(f"Server listening on {MSG_SERVER_IP}:{MSG_SERVER_PORT}")

        # Handle clients in a new thread
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Connection from {addr}")
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        # This function handles the client requests
        try:
            while True:
                # Receive data from the client
                data = client_socket.recv(1024)
                if not data:
                    break

                # Process the data (authentication, ticket granting, etc.)
                response = self.process_request(data)

                # Send response back to client
                client_socket.sendall(response)

        finally:
            client_socket.close()



    def is_valid_authenticator(self, authenticator, ticket):
        # Compare client IDs
        if authenticator['client_id'] != ticket['client_id']:
            return False

        # Verify server IDs
        if authenticator['server_id'] != ticket['server_id']:
            return False

        # Check version numbers
        if authenticator['version'] != ticket['version']:
            return False

        # Validate timestamps
        current_time = time.time()
        if authenticator['creation_time'] > current_time or ticket['creation_time'] > current_time:
            return False
        if ticket['expiration_time'] < current_time:
            return False

        return True
    
    def process_request(self, data):
        
        try:
            # Parse the request header
            client_id = data[:16]  # Client ID (16 bytes)
            version = data[16]  # Version (1 byte)
            code = int.from_bytes(data[17:19], 'big')  # Code (2 bytes)
            payload_size = int.from_bytes(data[19:23], 'big')  # Payload size (4 bytes)
            payload = data[23:23+payload_size]  # Payload

            # Handle registration request (Code 1028)
 
            if code == 1028:
                server_key = Tools.decode_base64_and_pad(MSG_SERVER_ENCRYPTION.encode())
                Authenticator = payload[57]
                authenticator_iv = Authenticator[:16]  # First 16 bytes
                encrypted_version = Authenticator[16:17]  # Next 1 byte
                encrypted_client_id = Authenticator[17:33]  # Next 16 bytes
                encrypted_server_id = Authenticator[33:49]  # Next 16 bytes
                encrypted_creation_time = Authenticator[49:57]  # Next 8 bytes

                # Decrypt each field using the AES key derived from the Ticket
                version = decrypt_key(server_key, authenticator_iv, encrypted_version)
                client_id = decrypt_key(server_key, authenticator_iv, encrypted_client_id)
                server_id = decrypt_key(server_key, authenticator_iv, encrypted_server_id)
                creation_time = decrypt_key(server_key, authenticator_iv, encrypted_creation_time)

                Ticket = payload[57:97]
                # Extract each field from the Ticket
                ticket_version = Ticket[0]
                ticket_client_id = Ticket[1:17]  # Bytes from 1 to 16
                ticket_server_id = Ticket[17:33]  # Bytes from 17 to 32
                ticket_creation_time = Ticket[33:41]  # Bytes from 33 to 40
                ticket_iv = Ticket[41:57]  # Bytes from 41 to 56
                ticket_encrypted_aes_key = Ticket[57:89]  # Bytes from 57 to 88
                ticket_encrypted_expiration_time = Ticket[89:97]  # Bytes from 89 to 96
                
                aes_key = decrypt_key(server_key,ticket_iv,ticket_encrypted_aes_key)
                expiration_time = decrypt_key(server_key,ticket_iv,ticket_encrypted_expiration_time)
                
                # Check if the authenticator is valid
                is_valid = self.is_valid_authenticator({
                    'client_id': client_id,
                    'server_id': server_id,
                    'version': version,
                    'creation_time': creation_time,
                }, {
                    'client_id': ticket_client_id,
                    'server_id': ticket_server_id,
                    'version': ticket_version,
                    'creation_time' : ticket_creation_time,
                    'expiration_time': expiration_time
                })

                if is_valid and self.client_manager.add_client(client_id, aes_key, expiration_time):
                    return (1604).to_bytes(2, 'big')
                else:
                    return (1609).to_bytes(2, 'big')
            pass

            if code == 1028: 
        except Exception as e:
        # Handle any exceptions and return an appropriate error message
            return (1609).to_bytes(2, 'big')
        


if __name__ == '__main__':
    server = MessageServer()
    server.start_server()