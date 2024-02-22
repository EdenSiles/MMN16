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