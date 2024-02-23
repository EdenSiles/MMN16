
import socket
import json


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

    response2 = send_request_to_server(name, password)
    version, response_code, client_id = parse_response(response2)

    # Validate the response
    if response_code == 1601:
        print(f"Test passed: Version: {version}, Response Code: {response_code}, Client ID: {client_id}")

def test_registration_repeated_request():
    # Name and password for registration
    name = 'test_client'
    password = 'test_password'

    # Send the first request
    response1 = send_request_to_server(name, password)
    print(f'Test Case - First Registration Attempt: Response - {response1}')

    # Send the same request again
    response2 = send_request_to_server(name, password)
    print(f'Test Case - Second Registration Attempt: Response - {response2}')

# Running the test
if __name__ == '__main__':
    test_registration_response_validation()
