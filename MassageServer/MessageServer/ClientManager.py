import time

class ClientManager:
    def __init__(self):
        self.clients = self.load_clients()

    def load_clients(self):
        clients = {}
        try:
            with open('clients', 'r') as file:
                for line in file:
                    client_id, aes_key, expiration_time = line.strip().split(':')
                    if time.time() < float(expiration_time):
                        clients[client_id] = {'aes_key': aes_key, 'expiration_time': expiration_time}
        except FileNotFoundError:
            pass
        return clients

    def remove_expired_clients(self):
        current_time = time.time()
        self.clients = {id: details for id, details in self.clients.items() if current_time < float(details['expiration_time'])}
        self.save_clients()

    def save_clients(self):
        self.remove_expired_clients()  # Clean up before saving
        with open('clients', 'w') as file:
            for client_id, details in self.clients.items():
                file.write(f"{client_id}:{details['aes_key']}:{details['expiration_time']}\n")

    def add_client(self, client_id, aes_key, expiration_time):
        self.remove_expired_clients()  # Clean up before adding a new client
        self.clients[client_id] = {'aes_key': aes_key, 'expiration_time': expiration_time}
        self.save_clients()
        return True

    def get_aes_key(self, client_id):
        self.remove_expired_clients()  # Clean up before getting a key
        if client_id in self.clients:
            client = self.clients[client_id]
            if time.time() < float(client['expiration_time']):
                return client['aes_key']
        return None
