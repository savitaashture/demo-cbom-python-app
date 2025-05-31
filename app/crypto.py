# Insecure crypto.py
import hashlib
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

def hash_password(pwd):
    return hashlib.md5(pwd.encode()).hexdigest()  # ❌ Insecure hash

def encrypt_user_data(username, password):
    key = b"12345678"  # ❌ Hardcoded weak key
    cipher = DES.new(key, DES.MODE_ECB)  # ❌ ECB mode
    data = f"{username}:{password}".encode()
    encrypted = cipher.encrypt(pad(data, 8))
    return base64.b64encode(encrypted).decode()