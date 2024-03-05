# client.py
import time
import socket
import uuid
import hashlib
from Tools import *
from EncryptionUtils import *
from Crypto.Random import get_random_bytes
from ClientConfig import *


# Constants
INFO_ME_FILE = "me.info"
INFO_SRV_FILE = "srv.info"

def read_info_me(): 
    try:
        with open(INFO_ME_FILE, 'r') as f:
            lines = f.readlines()
            if len(lines) >= 2:
                username = lines[0].strip()
                client_id = lines[1].strip()
                return username, client_id
            else:
                print("User not found")
                return None, None
    except FileNotFoundError:
        print("me.info file not found")
        return None, None
       
def write_user_info_to_file(username):
    # client_id = uuid.uuid1().hex
    with open('me.info', 'w') as f:
        f.write(f"{username}")

def read_srv_authenticator(line):
    try:
        with open(INFO_SRV_FILE, 'r') as f:
            if(line == 2):
                next(f)
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

def write_client_id_to_info_file(client_id):
    with open(INFO_ME_FILE, 'r') as file:
        lines = file.readlines()

    with open(INFO_ME_FILE, 'w') as file:
        file.write(lines[0].strip() + '\n')
        file.write(client_id)

def register_to_auth_server(name, password):
    
    server_ip, server_port = read_srv_authenticator(1)
    
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
    code = REGISTRATION  # Code for registration
    payload = (name + '\x00' + password + '\x00').encode('ascii')
    payload_size = len(payload)
    request = bytearray(16) + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big') + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(REGISTRATION)

    # Close the connection
    client_socket.close()

    return response.decode()

def request_symmetric_key(client_id):
    
    server_ip, server_port = read_srv_authenticator(1)
    
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((server_ip, server_port))
    except ConnectionRefusedError:
        client_socket.close()
        raise ConnectionRefusedError('Server is not responding. Ensure the server is running and accessible.')

    server_id = uuid.uuid4().bytes
    nonce = Tools.generate_crypto_nonce()

    # Construct the request
    version = 1  # Assuming version is 1
    code = GET_SYMETRIC_KEY  # Code for registration
    payload = server_id + nonce
    payload_size = len(payload)
    request = Tools.uuid_str_to_bytes(client_id) + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big') + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(GET_SYMETRIC_KEY)

    # Close the connection
    client_socket.close()

    return nonce, response

def generate_authenticator_and_send(client_id, Ticket, aes_key,version, server_id):
    creation_time =  int(time.time()).to_bytes(8, 'big')
    iv = get_random_bytes(16)
    combined_data = version.to_bytes(1, 'big') + client_id + server_id + creation_time
    #time_encrypted = encrypt_key(aes_key, iv, creation_time)#16
    #version_encrypted = encrypt_key(aes_key, iv, version.to_bytes(8, 'big'))#16
    #client_id_encrypted = encrypt_key(aes_key, iv, client_id)#32
    #server_id_encrypted = encrypt_key(aes_key, iv, server_id)#32
    
    combined_data_encrypted = encrypt_key(aes_key, iv, combined_data)
    authenticator = iv + combined_data_encrypted

    payload = authenticator + Ticket
    code = SEND_MSG_AUT
    payload_size = len(payload)
    header = client_id + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big')
    #authenticator = iv + version_encrypted + client_id_encrypted + server_id_encrypted + time_encrypted
    server_ip, server_port = read_srv_authenticator(2)
    
    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect to the server
    try:
        client_socket.connect((server_ip, server_port))
    except ConnectionRefusedError:
        client_socket.close()
        raise ConnectionRefusedError('Server is not responding. Ensure the server is running and accessible.')

    request = header + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(SEND_MSG_AUT)

    # Close the connection
    client_socket.close()

    return response

def send_a_message(content, aes_key, client_id, version):
  
    messageIV = get_random_bytes(16)
    
    content_bytes = content.encode('utf-8')

    contentEncrypted = encrypt_key(aes_key, messageIV, content_bytes)
    
    # Calculate the length of the byte string
    message_size = len(contentEncrypted)

    # Convert the size to 4 bytes
    message_size_bytes = message_size.to_bytes(4,'big')
    payload = message_size_bytes + messageIV + contentEncrypted
    
    code = SEND_MESSAGE
    payload_size = len(payload)
    header = client_id + version.to_bytes(1, 'big') + code.to_bytes(2, 'big') + payload_size.to_bytes(4, 'big')

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_ip, server_port = read_srv_authenticator(2)

    # Connect to the server
    try:
        client_socket.connect((server_ip, server_port))
    except ConnectionRefusedError:
        client_socket.close()
        raise ConnectionRefusedError('Server is not responding. Ensure the server is running and accessible.')

    request = header + payload

    # Send the request
    client_socket.sendall(request)

    # Receive the response
    response = client_socket.recv(SEND_MESSAGE)

    # Close the connection
    client_socket.close()

    return response

def parse_response(response):
    # Convert the response to bytes if it's a string
    if isinstance(response, str):
        response = response.encode()
    # Parsing the response into its components
    response_code = int.from_bytes(response[1:3], 'big')

    if (response_code == REGISTRATION_SUCCESSFUL):
        # version = response[0]
        payload_size = int.from_bytes(response[3:7], 'big')
        client_id = response[7:7+payload_size].decode().rstrip('\x00')
        return client_id
    
    if (response_code == REGISTRATION_FAIL):
        print ("Registration faild")

    if (response_code == GET_KEY_TICKET):
        payload_size = int.from_bytes(response[3:], 'big')
        client_id = response[7:23]
        encrypted_key = response[23:87]
        ticket = response[87:]
        return client_id, encrypted_key, ticket
    
    response_code = int.from_bytes(response[0:2], 'big')
    if (response_code == ACCEPT_SYMETRIC_KEY):
        return True

    if (response_code == ACCEPT_MESSAGE):
        return True

    if (response_code == SERVER_ERROR):
        return False


def main():

    username, client_id = read_info_me()

    if (username == None or username == '' or client_id == None or client_id == ''):
        username = input("Enter your Username: ")
        write_user_info_to_file(username)
        password = input("\nEnter your Password: ")
        try:
            response =register_to_auth_server(username, password)
            client_id = parse_response(response)
            write_client_id_to_info_file(client_id)
        except:
            print("Registration faild")
    else:
        print (f"Hello! {username}")
        password = input("\nEnter your Password: ")
    
    hashpassword = hashlib.sha256(password.encode()).hexdigest()
    
    try:
        new_nonce, response = request_symmetric_key(client_id)
        client_id, encrypted_key, Ticket = parse_response(response)
    except:
        print("Request failed - 1027/1603")
    
    try:
        version = Ticket[0]
        server_id = Ticket[17:33]
        nonce, aes_key = decrypt_key(encrypted_key, hashpassword)
        if (nonce == new_nonce):
            response = generate_authenticator_and_send(client_id, Ticket, aes_key, version, server_id)
            responseFlag = parse_response(response)
    except:
        print("Request failed - 1028/1609")

    while responseFlag == True:
        print("\nConnected")
        contnet = input("\nWrite a message: ")
        try:
            response = send_a_message(contnet, aes_key, client_id, version)
            responseFlag = parse_response(response)
        except:
            print("Sending the message failed")
        if responseFlag == True:
            print("\nSent")
        elif responseFlag == False:
            print("Server failed")

if __name__ == "__main__":
    main()