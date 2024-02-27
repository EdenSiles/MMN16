
import socket
import json
import uuid
from Crypto.Random import get_random_bytes



def send_request_to_server(name, password, server_ip='127.0.0.1', server_port=1234):

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((server_ip, server_port))
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

def test_request_ticket(client_id, server_id, server_ip='127.0.0.1', server_port=1234):
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((server_ip, server_port))
    except ConnectionRefusedError:
        client_socket.close()
        raise ConnectionRefusedError('Server is not responding. Ensure the server is running and accessible.')

    # Prepare the payload
    version = 1  # Assuming version is 1
    code = 1027  # Code for request 1027
    nonce = get_random_bytes(8)  # Generate an 8-byte nonce

    # Construct the request with Client ID, Version, Code, and Payload
    client_id_bytes = uuid_str_to_bytes(client_id)
    server_id_bytes = server_id.encode() if isinstance(server_id, str) else server_id  # Ensure server_id is bytes
    payload = server_id_bytes + nonce
    payload_size = len(payload)
    request = client_id_bytes  + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big') + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(1027)

    # Close the connection
    client_socket.close()

    # Parse and validate the response
    # Add your response parsing and validation logic here

    return response


def uuid_str_to_bytes(uuid_str):
    # Convert the UUID string to a UUID object
    uuid_obj = uuid.UUID(uuid_str)

    # Get the bytes of the UUID object
    uuid_bytes = uuid_obj.bytes

    # Pad the UUID bytes to 16 bytes if necessary (usually not needed for standard UUIDs)
    padded_uuid = uuid_bytes + b'\x00' * (16 - len(uuid_bytes))

    return padded_uuid



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

def test_registration_response_validation():
    # Name and password for registration
    name = 'test_client'
    password = 'test_password'

    # Send the request
    response1 = send_request_to_server(name, password)
    version, response_code, client_id = parse_response(response1)

    # Validate the response
    if response_code == 1600:
        print(f"Test passed: Version: {version}, Response Code: {response_code}, Client ID: {client_id}")
    
    
    response1 = test_request_ticket(client_id, '64f3f63985f04beb81a0e43321880182')
    version, response_code, client_id = parse_response(response1)
    print(f"Test passed: Version: {version}, Response Code: {response_code}, Client ID: {client_id}")

    # Validate the response
    if response_code == 1601:
        print(f"Test passed: Version: {version}, Response Code: {response_code}, Client ID: {client_id}")

# Running the test
if __name__ == '__main__':
    test_registration_response_validation()






