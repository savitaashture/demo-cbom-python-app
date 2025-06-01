# Secure crypto.py
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

def hash_password(pwd):
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(pwd.encode())
    return digest.finalize().hex()

def encrypt_user_data(username, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    data = f"{username}:{password}".encode()
    padded_data = PKCS7(128).padder().update(data) + PKCS7(128).padder().finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted).decode()