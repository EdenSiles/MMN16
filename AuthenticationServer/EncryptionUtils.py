from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_expiration_time_ticket(aes_key ,messages_server_key ,expiration_time):
    # Generate Ticket IV - 16 bytes
    ticket_iv = get_random_bytes(16)

    # Create a cipher object using the client's symmetric key
    cipher = AES.new(messages_server_key, AES.MODE_CBC, ticket_iv)

    combined_data = aes_key + expiration_time

    encrypted_combined_data = cipher.encrypt(pad(combined_data, AES.block_size))

    return ticket_iv, encrypted_combined_data
    


def generate_encrypted_key_and_iv(client_symmetric_key, nonce):
    # Generate a random AES key (32 bytes for AES-256)
    aes_key = get_random_bytes(32)

    combined_data = nonce + aes_key
    # Generate a random IV (16 bytes)
    iv = get_random_bytes(16)

    # Create a cipher object using the client's symmetric key
    cipher = AES.new(client_symmetric_key, AES.MODE_CBC, iv)

    encrypted_combined_data = cipher.encrypt(pad(combined_data, AES.block_size))

    return aes_key, iv, encrypted_combined_data

    
