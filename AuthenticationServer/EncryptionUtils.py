from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_expiration_time_ticket(aes_key ,messages_server_key ,expiration_time):
    # Generate Ticket IV - 16 bytes
    ticket_iv = get_random_bytes(16)

    # Initialize cipher with the provided AES key and the generated IV
    cipher = AES.new(messages_server_key, AES.MODE_CBC, ticket_iv)

    # Encrypt
    encrypted_aes = cipher.encrypt(pad(aes_key, AES.block_size))

    # Encrypt the Expiration Time
    encrypted_expiration_time = cipher.encrypt(pad(expiration_time, AES.block_size))

    # Extract the first 8 bytes as encrypted nonce and the next 32 bytes as encrypted AES key
    encrypted_aes = encrypted_aes[:32]
    encrypted_expiration_time = encrypted_expiration_time[:8]

    return ticket_iv, encrypted_aes, encrypted_expiration_time
    


def generate_encrypted_key_and_iv(client_symmetric_key, nonce):
    # Generate a random AES key (32 bytes for AES-256)
    aes_key = get_random_bytes(32)

    # Generate a random IV (16 bytes)
    iv = get_random_bytes(16)

 # Create a cipher object using the client's symmetric key
    cipher = AES.new(client_symmetric_key, AES.MODE_CBC, iv)

    # Encrypt and pad the nonce
    encrypted_nonce = cipher.encrypt(pad(nonce, AES.block_size))

    # Reinitialize cipher for AES key encryption
    cipher = AES.new(client_symmetric_key, AES.MODE_CBC, iv)
    encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))
     
    # Extract the first 8 bytes as encrypted nonce and the next 32 bytes as encrypted AES key
    encrypted_nonce = encrypted_nonce[:8]
    #encrypted_aes_key = encrypted_aes_key[:32]

    return aes_key, iv, encrypted_nonce, encrypted_aes_key

    
