from EncryptionUtils import *
from ServerConfig import *
import time
import struct
from Tools import *
from Crypto.Random import get_random_bytes

class TicketManager:
    def __init__(self):
        self.tickets = {}  # Dictionary to store tickets

    def generate_encrypted_key_and_ticket(self, verison, client_id, client_key, server_id, nonce, messages_server_encryption):
        # Generate an encrypted key and IV


        aes_key, encrypted_key_iv, encrypted_nonce, encrypted_aes_key = generate_encrypted_key_and_iv(client_key, nonce)
        encrypted_key = encrypted_key_iv + encrypted_nonce + encrypted_aes_key
        ticket = self.create_ticket(verison, client_id, server_id, aes_key, messages_server_encryption)
        return encrypted_key, ticket   



    def create_ticket(self, version, client_id, server_id, aes_key, messages_server_encryption):
        
        # Version - 1 byte
        version_byte = version.to_bytes(1, 'big')

        # Creation Time - 8 bytes (Epoch time)
        creation_time = int(time.time()).to_bytes(8, 'big')

        ticket_iv, encrypted_aes, encrypted_expiration_time = encrypt_expiration_time_ticket(aes_key, messages_server_encryption , (int(time.time()) + 86400).to_bytes(8, 'big'))
        
        # Combine all parts to form the ticket
        ticket = version_byte + client_id + server_id + creation_time + ticket_iv + encrypted_aes + encrypted_expiration_time
        length = len(ticket)
        return ticket