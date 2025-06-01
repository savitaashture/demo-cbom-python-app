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

# Cryptographic Assets
# Algorithm: AES, RSA, SHA256
# Certificate: X.509 certificates for identity verification
# Protocol: TLS/SSL for secure communication
# Private Key: Used for RSA signing and decryption
# Public Key: Used for RSA encryption and signature verification
# Secret Key: Used in AES symmetric encryption
# Key: General term for cryptographic keys
# Ciphertext: Encrypted data output
# Signature: Digital signature for data integrity
# Digest: SHA256 hash for data integrity
# Initialization Vector: Random value for AES encryption freshness
# Nonce: Unique value for preventing replay attacks
# Seed: Starting point for random number generation
# Salt: Random value for password hardening
# Shared Secret: Secret shared between two parties for secure communication
# Tag: Authentication tag for AES-GCM encryption
# Additional Data: Extra information for encryption context
# Password: User-provided secret for authentication
# Credential: Passwords, keys, or certificates proving identity
# Token: Temporary identity reference for authentication
# Other: Custom cryptographic asset
# Unknown: Unclassified cryptographic item

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import Hash, SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import base64
import os

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

# Generate a secret key using PBKDF2
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
password = b"user-provided-password"
secret_key = kdf.derive(password)

# Generate a digest for data integrity
message = b"Important data"
digest = Hash(SHA256(), backend=default_backend())
digest.update(message)
message_digest = digest.finalize()

# Generate a seed for randomness
seed = os.urandom(32)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Serialize keys
private_key_pem = private_key.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
)

# Encrypt data using the public key
def encrypt_with_public_key(data):
    ciphertext = public_key.encrypt(
        data.encode(),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return base64.b64encode(ciphertext).decode()

# Decrypt data using the private key
def decrypt_with_private_key(ciphertext):
    plaintext = private_key.decrypt(
        base64.b64decode(ciphertext),
        OAEP(
            mgf=MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Example usage
data = "Sensitive information"
ciphertext = encrypt_with_public_key(data)
decrypted_data = decrypt_with_private_key(ciphertext)