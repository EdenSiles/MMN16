import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import hashlib
import ast
import os

#constant
WAIT_TIME = 0.01

def load_ciphertext(ciphertext_file):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(script_dir)
    # Load ciphertext from a file.
    with open(ciphertext_file, 'r') as file:
        # Read the content
        content = file.read()
        # Evaluate the string representation to convert it to bytes
        return ast.literal_eval(content)
    
def load_dictionary(password_file):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    os.chdir(script_dir)
    #Load potential passwords from a file.
    with open(password_file, 'r') as file:
        return file.read().splitlines()

def hash_password(password, hash_algorithm='sha256'):
    #Hash a password using the specified algorithm.
    return hashlib.new(hash_algorithm, password.encode()).hexdigest()

def decrypt_key(encrypted_key, hashpassword):
    try:
        key = bytes.fromhex(hashpassword)
        iv = encrypted_key[:16]
        encrypted_value = encrypted_key[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_value = unpad(cipher.decrypt(encrypted_value), AES.block_size)
        if(decrypted_value[8:40]):
            return True
    except Exception as e:
        return False

def decrypt_try(hardcoded_ciper_text, key):
    encrypted_key = hardcoded_ciper_text[23:87] 
    aes_key = decrypt_key(encrypted_key, key)
    if aes_key:
        return True
    else:
        return False


def perform_attack(hardcoded_ciper_text, dictionary):
    #Try each password in the dictionary to find a match with the target hash.
    for password in dictionary:
        key = hash_password(password)
        time.sleep(WAIT_TIME)
        if(decrypt_try(hardcoded_ciper_text, key)):
            print("Decryption Succeeded with password: " + password)
            return True
        else:
            print("Decryption failed with password: " + password)     
    return False

if __name__ == "__main__":
    # Hardcoded hash extracted from communication
    hardcoded_ciper_text = load_ciphertext("cipertext.txt")

    # Load the dictionary of potential passwords
    dictionary = load_dictionary("dictionary.txt")

    # Perform the dictionary attack
    cracked_password = perform_attack(hardcoded_ciper_text, dictionary)

    if cracked_password:
        print(f"Password cracked: {cracked_password}")
    else:
        print("Password could not be cracked with the provided dictionary.")