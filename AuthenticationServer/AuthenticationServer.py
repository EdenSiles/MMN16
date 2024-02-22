import socket
import threading

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
        SERVER_IP = server_details[0].split(':')[0]
        SERVER_PORT = int(server_details[0].split(':')[1])
        SERVER_NAME = server_details[1]
        SERVER_IDENTIFIER = server_details[2]
        SERVER_ENCRYPTION_KEY = server_details[3]
except FileNotFoundError:
    print("Warning: 'info.msg' file not found. Default server details will be used.")
    # Default details (These should be replaced with actual default values)
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 1234
    SERVER_NAME = 'DefaultServer'
    SERVER_IDENTIFIER = '0000000000000000'
    SERVER_ENCRYPTION_KEY = 'DefaultKey'
PROTOCOL_VERSION = '24'  # Protocol version
from ClientManager import *
from TicketManager import *
from EncryptionUtils import *

class AuthenticationServer:
    def __init__(self):
        self.client_manager = ClientManager()
        self.ticket_manager = TicketManager()
        # Initialize other necessary components like database connections if required

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
            request = eval(data.decode())

            if request.get("action") == "register":
                client_id = request.get("client_id")
                credentials = request.get("credentials")

                # Call add_client from ClientManager
                registration_successful = self.client_manager.add_client(client_id, credentials)

                if registration_successful:
                    return '{"status": "success"}'.replace(' ', '').encode()
                else:
                    return '{"status": "failure", "error": "Client already exists"}'.replace(' ', '').encode()
            else:
                # Handle other types of requests
                pass

        except Exception as e:
            # Handle any exceptions and return an appropriate error message
            return '{"status": "failure", "error": str(e)}'.replace(' ', '').encode()

if __name__ == '__main__':
    server = AuthenticationServer()
    server.start_server()