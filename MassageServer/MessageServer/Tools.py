import base64

class Tools:
    
    def decode_base64_and_pad(base64_string):
        # Decode the Base64 string
        decoded_bytes = base64.b64decode(base64_string)

        return decoded_bytes
    
