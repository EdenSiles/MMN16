from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_key(aes_key, iv, encrypted_value):
    # Initialize cipher with the provided AES key and the generated IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt
    decrypted_value = cipher.decrypt(encrypted_value)

    # Unpad
    decrypted_value = unpad(decrypted_value, AES.block_size)

    return decrypted_value