from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
import base64

def encrypt_user_data(username, password):
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

def hash_password(pwd):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(pwd.encode())
    return digest.finalize().hex()