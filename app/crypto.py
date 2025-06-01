# This code is intentionally insecure and should not be used in production.
# It is provided for educational purposes only to demonstrate poor cryptographic practices.

'''
| Aspect         | Issue                         |
| -------------- | ----------------------------- |
| Hardcoded Key  | Easy to guess/crack           |
| Fixed IV       | Vulnerable to pattern attacks |
| ECB Mode       | No integrity check            |
| Manual Padding | Easy to corrupt or exploit    |
| No KDF or Salt | Password reused as-is         |
'''

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
import base64

def encrypt_user_data(username, password):
    key = b'12345678'  # Hardcoded weak key
    iv = b'\x00' * 8  # Fixed IV

    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())  # Insecure ECB mode
    encryptor = cipher.encryptor()

    plaintext = f"{username}:{password}".encode()

    # Manual padding
    padding_length = 8 - (len(plaintext) % 8)
    padded = plaintext + bytes([padding_length]) * padding_length

    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode()

def hash_password(pwd):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(pwd.encode())
    return digest.finalize().hex()