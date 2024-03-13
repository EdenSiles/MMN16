import hashlib
import uuid
import time
import os

class ClientManager:
    def __init__(self):
        # Initialize a dictionary to store client details
        self.clients = self.load_clients()

    def load_clients(self):
        # Load clients from the 'clients' file if it exists
        clients = {}
        script_dir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(script_dir)
        try:
            with open('clients', 'r') as file:
                for line in file:
                    id, name, password_hash, last_seen = line.strip().split(':')
                    clients[id] = {'Name': name, 'PasswordHash': password_hash, 'LastSeen': last_seen}
        except FileNotFoundError:
            pass  # No clients file exists yet
        return clients

    def save_clients(self):
        script_dir = os.path.dirname(os.path.realpath(__file__))
        os.chdir(script_dir)
        # Save clients to the 'clients' file
        with open('clients', 'w') as file:
            for id, details in self.clients.items():
                file.write(f"{id}:{details['Name']}:{details['PasswordHash']}:{details['LastSeen']}\n")

    def add_client(self, name, password):
        # Check if a client with the same name already exists
        for existing_client_id, details in self.clients.items():
            if details['Name'] == name:
                return False, None  # Client with the same name exists

        # Generate a unique ID for the client and create a password hash
        client_id = str(uuid.uuid4())
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        # Add the new client to the dictionary
        self.clients[client_id] = {
            'Name': name,
            'PasswordHash': password_hash,
            'LastSeen': time.time()  # Use an appropriate timestamp or placeholder
        }

        # Save the updated clients list
        self.save_clients()

        # Return success status and the new client_id
        return True, client_id

    def authenticate_client(self, client_id, password):
        # Authenticate a client based on password
        if client_id in self.clients:
            stored_password_hash = self.clients[client_id]['PasswordHash']
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return stored_password_hash == password_hash
        else:
            return False

    def pass_client(self, client_id):
        return self.clients[client_id]['PasswordHash']
        #Check if client exists
    def check_client(self, client_id):
        if client_id in self.clients:
            self.update_last_seen(client_id)
            return True
        else:
            return False

    def update_last_seen(self, client_id):
        # Update the last seen time for a client
        if client_id in self.clients:
            self.clients[client_id]['LastSeen'] = time.time()
            self.save_clients()
            return True
        else:
            return False
