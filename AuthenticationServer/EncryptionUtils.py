from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def encrypt_message(message, key):
    # Initialize AES cipher in CBC mode with a random IV
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Encrypt the message
    # Ensure that the message is a multiple of the block size by padding it
    encrypted_message = cipher.encrypt(pad(message.encode(), AES.block_size))

    # Return the IV and the encrypted message
    # They are both needed for decryption
    return iv + encrypted_message

def decrypt_message(encrypted_message, key):
    # The IV is the first 16 bytes of the encrypted message
    iv = encrypted_message[:AES.block_size]

    # The actual encrypted message is after the IV
    encrypted_message = encrypted_message[AES.block_size:]

    # Initialize the AES cipher in CBC mode for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the message and unpad it
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)

    # Convert the message back to a string
    return decrypted_message.decode()

def generate_encrypted_key_and_iv(key, nonce):
    # Function to generate an encrypted key and IV using the given key and nonce
    aes_key = get_random_bytes(32)  # 32 bytes for AES-256
    iv = get_random_bytes(AES.block_size)  # IV for encryption

    # Encrypt the nonce and the generated AES key
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_nonce = cipher.encrypt(pad(nonce, AES.block_size))
    encrypted_aes_key = cipher.encrypt(pad(aes_key, AES.block_size))

    # Return the IV, encrypted nonce, and encrypted AES key
    return iv, encrypted_nonce, encrypted_aes_key
