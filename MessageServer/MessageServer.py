import socket
import threading
import time
import uuid
from ClientManager import *
from EncryptionUtils import decrypt_key
from ServerConfig import *
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
                data = client_socket.recv(1605)
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
        int.from_bytes(ticket['expiration_time'], 'big')
        if int.from_bytes(authenticator['creation_time'], 'big') > current_time or int.from_bytes(ticket['creation_time'], 'big') > current_time:
            return False
        if int.from_bytes(ticket['expiration_time'], 'big') < current_time:
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
 
            if code == SEND_SYMETRIC_KEY:

                server_key = Tools.decode_base64_and_pad(MSG_SERVER_ENCRYPTION.encode())
                Ticket = payload[64:]
                # Extract each field from the Ticket
                ticket_version = Ticket[0]
                ticket_client_id = Ticket[1:17]
                ticket_server_id = Ticket[17:33]  
                ticket_creation_time = Ticket[33:41]  
                ticket_iv = Ticket[41:57]  

                combined_data = decrypt_key(server_key, ticket_iv, Ticket[57:])
                aes_key = combined_data[:32] 
                expiration_time = combined_data[32:]  
                
                Authenticator = payload[:64]
                authenticator_iv = Authenticator[:16]  # First 16 bytes
                combined_data = decrypt_key(aes_key, authenticator_iv, Authenticator[16:])
                version = combined_data[0]  # Next 1 byte
                client_id = combined_data[1:17]  # Next 16 bytes
                server_id = combined_data[17:33]  # Next 16 bytes
                creation_time = combined_data[33:]  # Next 8 bytes
                
           
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

                if is_valid and self.client_manager.add_client(str(uuid.UUID(bytes=client_id)), aes_key.hex(), float(int.from_bytes(expiration_time, 'big'))):
                    code = ACCEPT_SYMETRIC_KEY
                    response = code.to_bytes(2, 'big')
                    return response
                else:
                    code = SERVER_ERROR
                    response = code.to_bytes(2, 'big')
                    return response
            pass

            if code == SEND_MESSAGE:
                    
                    message_size = payload[:4]
                    message_iv = payload[4:20]
                    message_content = payload[20:]
                    client_key = self.client_manager.get_aes_key(str(uuid.UUID(bytes=client_id)))
                    if(client_key != None):
                        client_key = bytes.fromhex(client_key)
                        code = ACCEPT_MESSAGE
                        massage = decrypt_key(client_key, message_iv, message_content)
                        print(massage.decode('utf-8'))
                    else:
                        code = SERVER_ERROR
                        print('error in server')

                    response = code.to_bytes(2, 'big')
                    return response
                    
        except Exception as e:
        # Handle any exceptions and return an appropriate error message
            code = SERVER_ERROR
            print('error in server')
            response = code.to_bytes(2, 'big')
            return response
        


if __name__ == '__main__':
    server = MessageServer()
    server.start_server()