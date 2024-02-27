import base64

class Tools:
    
    def decode_base64_and_pad(base64_string):
        # Decode the Base64 string
        decoded_bytes = base64.b64decode(base64_string)

        return decoded_bytes


    def adjust_byte_length(byte_string, target_length, padding_byte=b'\x00'):
        # Truncate the byte string if it's too long
        if len(byte_string) > target_length:
            return byte_string[:target_length]
        # Pad the byte string if it's too short
        elif len(byte_string) < target_length:
            padding_needed = target_length - len(byte_string)
            return byte_string + padding_byte * padding_needed
        return byte_string
    
    def hex_string_to_padded_bytes(hex_string, total_length, padding_byte=b'\x00'):
        # Convert the hex string to bytes
        byte_data = bytes.fromhex(hex_string)

        # Calculate the number of padding bytes needed
        padding_length = total_length - len(byte_data)

        # Check if padding is needed
        if padding_length < 0:
             raise ValueError("Total length is less than the length of the hex string")

        # Add padding
        padded_data = byte_data + (padding_byte * padding_length)

        return padded_data