
import hashlib
import uuid

class ClientManager:
    def __init__(self):
        # Initialize a dictionary to store client details
        self.clients = self.load_clients()

    def load_clients(self):
        # Load clients from the 'clients' file if it exists
        clients = {}
        try:
            with open('clients', 'r') as file:
                for line in file:
                    id, name, password_hash, last_seen = line.strip().split(':')
                    clients[id] = {'Name': name, 'PasswordHash': password_hash, 'LastSeen': last_seen}
        except FileNotFoundError:
            pass  # No clients file exists yet
        return clients

    def save_clients(self):
        # Save clients to the 'clients' file
        with open('clients', 'w') as file:
            for id, details in self.clients.items():
                file.write(f"{id}:{details['Name']}:{details['PasswordHash']}:{details['LastSeen']}\n")

    def add_client(self, name, password):
        # Add a new client to the clients dictionary
        client_id = str(uuid.uuid4())  # Generate a unique ID for the client
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        if client_id not in self.clients:
            self.clients[client_id] = {
                'Name': name,
                'PasswordHash': password_hash,
                'LastSeen': 'Never'  # Use an appropriate timestamp or placeholder
            }
            self.save_clients()
            return True, client_id
        else:
            return False, None

    def authenticate_client(self, client_id, password):
        # Authenticate a client based on credentials
        if client_id in self.clients:
            stored_password_hash = self.clients[client_id]['PasswordHash']
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            return stored_password_hash == password_hash
        else:
            return False

    def update_last_seen(self, client_id, timestamp):
        # Update the last seen time for a client
        if client_id in self.clients:
            self.clients[client_id]['LastSeen'] = timestamp
            self.save_clients()
            return True
        else:
            return False
