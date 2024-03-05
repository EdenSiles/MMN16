from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


def encrypt_key(aes_key ,iv ,to_ecrypt):
    # Initialize cipher with the provided AES key and the generated IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)

    # Encrypt
    encrypted_value = cipher.encrypt(pad(to_ecrypt, AES.block_size))

    return encrypted_value

def decrypt_key(encrypted_key, hashpassword):
    key = bytes.fromhex(hashpassword)
    iv = encrypted_key[:16]
    encrypted_value = encrypted_key[16:]
    # Initialize cipher with the provided AES key and the generated IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Decrypt
    decrypted_value = unpad(cipher.decrypt(encrypted_value), AES.block_size)
    nonce = decrypted_value[:8]
    aes_key = decrypted_value[8:40]
    return nonce, aes_key

    
