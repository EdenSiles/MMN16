import base64
import secrets
import uuid

class Tools:
    
    def uuid_str_to_bytes(uuid_str):
        # Convert the UUID string to a UUID object
        uuid_obj = uuid.UUID(uuid_str)

        # Get the bytes of the UUID object
        uuid_bytes = uuid_obj.bytes

        # Pad the UUID bytes to 16 bytes if necessary (usually not needed for standard UUIDs)
        padded_uuid = uuid_bytes + b'\x00' * (16 - len(uuid_bytes))

        return padded_uuid
    
    def generate_crypto_nonce():
        return secrets.token_bytes(8)