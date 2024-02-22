import time
from EncryptionUtils import encrypt_message, decrypt_message
from ServerConfig import *

class TicketManager:
    def __init__(self):
         # Initialize ticket storage, this could be a database or an in-memory store
        self.tickets = {}

    def create_ticket(self, client_id):
        # Create a ticket for the client
        # A ticket could contain client_id, timestamp, and other relevant data
        ticket_info = {
            'client_id': client_id,
            'timestamp': time.time(),
            # You can add more fields as per requirement
        }

        # Convert ticket info to string and encrypt it
        ticket_string = str(ticket_info)
        encrypted_ticket = encrypt_message(ticket_string, ENCRYPTION_KEY)

        # Store the ticket in the ticket storage
        self.tickets[client_id] = encrypted_ticket

        return encrypted_ticket

    def validate_ticket(self, ticket):
         # Decrypt the ticket
        try:
            decrypted_ticket = decrypt_message(ticket, ENCRYPTION_KEY)
            ticket_info = eval(decrypted_ticket)  # Convert string back to dictionary

            # Validate the ticket (e.g., check timestamp, client_id, etc.)
            if ticket_info['timestamp'] + TICKET_VALIDITY_DURATION > time.time():
                return True
            else:
                return False
        except Exception as e:
            print("Error in ticket validation:", e)
            return False