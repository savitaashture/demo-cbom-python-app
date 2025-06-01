# Though this code is secure for educational purposes only and should not be used in production.
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
