from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

def encrypt_user_data_insecure(username, password):
    key = b'0123456789abcdef'  # Hardcoded static key (BAD)
    iv = b'\x00' * 16          # Fixed IV (BAD)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))  # No integrity mode
    encryptor = cipher.encryptor()

    plaintext = f"{username}:{password}".encode()

    # Manual, improper padding (and insecure mode)
    padding_length = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([padding_length]) * padding_length

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()