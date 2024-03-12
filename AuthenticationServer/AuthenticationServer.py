import socket
import threading
from EncryptionUtils import *
from ClientManager import *
from TicketManager import *
from EncryptionUtils import *
from ServerConfig import *
# Read server port from 'info.port' file
try:
    with open('info.port', 'r') as file:
        SERVER_PORT = int(file.read().strip())
except FileNotFoundError:
    print("Warning: 'info.port' file not found. Using default port.")
    SERVER_PORT = 1256  # Default port

# Read server details from 'info.msg' file
try:
    with open('info.msg', 'r') as file:
        server_details = file.read().splitlines()
        MESSAGES_SERVER_IP = server_details[0].split(':')[0]
        MESSAGES_SERVER_PORT = int(server_details[0].split(':')[1])
        MESSAGES_SERVER_NAME = server_details[1]
        MESSAGES_SERVER_IDENTIFIER = server_details[2]
        MESSAGES_SERVER_ENCRYPTION = server_details[3]
except FileNotFoundError:
    print("Warning: 'info.msg' file not found. Default server details will be used.")
    # Default details (These should be replaced with actual default values)
    MESSAGES_SERVER_IP = '127.0.0.1'
    MESSAGES_SERVER_PORT = 1235
    MESSAGES_SERVER_NAME = 'Printer 20'
    MESSAGES_SERVER_IDENTIFIER = '64f3f63985f04beb81a0e43321880182'
    MESSAGES_SERVER_ENCRYPTION = 'x/wTp6+VCpH3hnSo0Ha46Q=='


class AuthenticationServer:
    def __init__(self):
        self.client_manager = ClientManager()
        self.ticket_manager = TicketManager()

    def start_server(self):
        # Create a socket object
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind to the server IP and port from ServerConfig
        server_socket.bind((SERVER_IP, SERVER_PORT))

        # Start listening for client connections
        server_socket.listen(5)
        print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

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

    def process_request(self, data):
        
        try:
            # Parse the request header
            client_id = data[:16]  # Client ID (16 bytes)
            version = data[16]  # Version (1 byte)
            code = int.from_bytes(data[17:19], 'big')  # Code (2 bytes)
            payload_size = int.from_bytes(data[19:23], 'big')  # Payload size (4 bytes)
            payload = data[23:23+payload_size]  # Payload

            # Handle registration request (Code 1024)
            if code == REGISTRATION:
                time.sleep(WAIT_TIME)
                print("Registration Process")
                # Extract Name and Password from payload (null-terminated strings)
                name, password = payload.split(b'\x00')[:2]
                name = name.decode('ascii').rstrip('\x00')
                password = password.decode('ascii').rstrip('\x00')
                # Call add_client from ClientManager (ignoring client_id)
                registration_successful, new_client_id = self.client_manager.add_client(name, password)
                if registration_successful:
                    time.sleep(WAIT_TIME)
                    print('User: ' + name + ' registered successfuly')
                    # Code for successful registration
                    response_code = REGISTRATION_SUCCESSFUL
                    response_header = version.to_bytes(1, 'big') + response_code.to_bytes(2, 'big')
                    client_id_bytes = new_client_id.encode() + b'\x00' * (16 - len(new_client_id))
                    payload_size = len(client_id_bytes)
                    return response_header + payload_size.to_bytes(4, 'big') + client_id_bytes
                else:
                    time.sleep(WAIT_TIME)
                    print('User:' + name + 'register fail')
                    # Code for registration failure
                    response_code = REGISTRATION_FAIL
                    response_header = version.to_bytes(1, 'big') + response_code.to_bytes(2, 'big')
                    payload_size = 0  # No payload for failure response
                    return response_header + payload_size.to_bytes(4, 'big')
                
            elif code == GET_SYMETRIC_KEY:               
                # Extract Messages Server ID and Nonce from payload
                server_id = payload[:16]
                nonce = payload[16:24]
                client_id_str = str(uuid.UUID(bytes=client_id))
                if self.client_manager.check_client(client_id_str):
                    time.sleep(WAIT_TIME)
                    print('User Connected successfuly')
                    # Generate Encrypted key and Ticket
                    encrypted_key, ticket = self.ticket_manager.generate_encrypted_key_and_ticket(version, client_id, bytes.fromhex(self.client_manager.pass_client(client_id_str)), server_id, nonce, Tools.decode_base64_and_pad(MESSAGES_SERVER_ENCRYPTION.encode()))
                
                    # Construct response
                    response_code = SEND_KEY  # Code for sending an encrypted symmetric key
                    payload_response = client_id + encrypted_key + ticket
                    payload_size = len(payload_response)
                    response_header = version.to_bytes(1, 'big') + response_code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big')
                    time.sleep(WAIT_TIME)
                    print('Ticket and Encrypted Key sent')
                    return response_header + payload_response

            else:
                # Handle other types of requests
                pass

        except Exception as e:
            # Handle any exceptions and return an appropriate error message
            return f'{{"status": "failure", "error": "{str(e)}"}}'.encode()




        
if __name__ == '__main__':
    server = AuthenticationServer()
    server.start_server()