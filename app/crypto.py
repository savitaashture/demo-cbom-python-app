import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

def list_crypto_assets():
    assets = []

    # AES Encryption
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    assets.append("AES Encryption")

    # SHA256 Hashing
    digest = Hash(SHA256(), backend=default_backend())
    digest.update(b"example data")
    assets.append("SHA256 Hash")

    # PBKDF2 Key Derivation
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(b"password")
    assets.append("PBKDF2 Key Derivation")

    # RSA Key Pair Generation
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    assets.append("RSA Key Pair")

    # Serialize RSA Keys
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    assets.append("Serialized RSA Keys")

    # Encrypt Data with RSA Public Key
    encrypted_data = public_key.encrypt(
        b"Sensitive information",
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    assets.append("RSA Encryption")

    # Decrypt Data with RSA Private Key
    decrypted_data = private_key.decrypt(
        encrypted_data,
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    assets.append("RSA Decryption")

    return assets

if __name__ == "__main__":
    crypto_assets = list_crypto_assets()
    print("Cryptographic Assets Detected:")
    for asset in crypto_assets:
        print(f"- {asset}")
