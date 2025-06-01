'''# This code is intentionally insecure and should not be used in production.
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
'''
# Though this code is secure for educational purposes only and should not be used in production.

'''
Secure features considered
Securely encrypt user data using AES-GCM with PBKDF2 key derivation.
AES-GCM = Confidentiality + Authentication
Random salt + IV per session
PBKDF2 = Password-based key derivation
Auth tag ensures tamper detection
No unnecessary padding (GCM doesn’t require it)
'''

from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

def hash_password(pwd):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(pwd.encode())
    return digest.finalize().hex()

def encrypt_user_data(username, password):
    salt = os.urandom(16)  # Unique salt per encryption
    iv = os.urandom(12)    # 12 bytes for AES-GCM
    backend = default_backend()

    # Key derivation using PBKDF2 with salt
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    # AES-GCM provides confidentiality + integrity
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=backend)
    encryptor = cipher.encryptor()

    plaintext = f"{username}:{password}".encode()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag

    # Final output: salt + iv + tag + ciphertext
    return base64.b64encode(salt + iv + tag + ciphertext).decode()
