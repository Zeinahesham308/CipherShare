import os
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import json
# Hash password with PBKDF2 and random salt
def hash_password_with_salt(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode())
    return base64.b64encode(hashed_password).decode(), base64.b64encode(salt).decode()
def derive_hash_with_existing_salt(password, salt_b64):
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived = kdf.derive(password.encode())
    return base64.b64encode(derived).decode()

# Verify a password using stored hash and salt
def verify_password_with_salt(password, stored_hash, stored_salt):
    salt = base64.b64decode(stored_salt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode(), base64.b64decode(stored_hash))
        return True
    except Exception:
        return False






def hash_password(password: str) -> str:
    """
    Hashes a password using SHA-256.
    Args:
        password (str): The plain-text password.
    Returns:
        str: The hashed password as a hexadecimal string.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# Derive encryption key from password and stored salt
def derive_key_from_password(password, salt_b64):
    salt = base64.b64decode(salt_b64)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def generate_random_key():
    return os.urandom(32)  # AES-256


# -------------- ENCRYPTION ------------------
def encrypt_file(filepath, key):
    with open(filepath, 'rb') as f:
        data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to 16 bytes
    pad_len = 16 - len(data) % 16
    data += bytes([pad_len] * pad_len)

    encrypted = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted  # Send IV with ciphertext


# -------------- DECRYPTION ------------------
def decrypt_file(filepath, key):
    """
    Decrypts a file encrypted with AES-CBC, handling potential padding issues.

    Args:
        filepath (str): Path to the encrypted file
        key (bytes): The decryption key
    """
    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        # Extract IV (first 16 bytes)
        iv = content[:16]
        encrypted = content[16:]

        # Check if we need to adjust the encrypted data
        if len(encrypted) % 16 != 0:
            print(f"[Warning] Encrypted data length ({len(encrypted)} bytes) is not a multiple of 16.")

            # Add padding to make it a multiple of 16
            padding_needed = 16 - (len(encrypted) % 16)
            encrypted += bytes([0] * padding_needed)
            print(f"Added {padding_needed} bytes of padding to make length a multiple of 16.")

        # Initialize cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        padded_plaintext = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        try:
            pad_len = padded_plaintext[-1]
            # Safety check: pad_len must be between 1 and 16
            if not (1 <= pad_len <= 16):
                print(f"[Warning] Invalid padding length: {pad_len}. Using alternative padding removal.")
                # Just use the data as is
                plaintext = padded_plaintext
            else:
                # Verify that all padding bytes have the same value
                padding_valid = all(b == pad_len for b in padded_plaintext[-pad_len:])
                if padding_valid:
                    plaintext = padded_plaintext[:-pad_len]
                else:
                    print("[Warning] Invalid padding format. Using data as is.")
                    plaintext = padded_plaintext
        except IndexError:
            # If something goes wrong with padding removal, return data as is
            plaintext = padded_plaintext

        # Write decrypted data back to file
        with open(filepath, 'wb') as f:
            f.write(plaintext)

        print(f"[Success] File decrypted successfully: {filepath}")
        return True

    except Exception as e:
        print(f"[Error] Decryption failed: {str(e)}")
        raise


# -------------- HASHING ------------------
def hash_file(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_fernet_key_from_password(password: str, salt: bytes) -> bytes:


    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_and_save_credentials(file_path, data_dict, fernet_key):
    f = Fernet(fernet_key)
    encrypted = f.encrypt(json.dumps(data_dict).encode())
    with open(file_path, 'wb') as file:
        file.write(encrypted)

def load_and_decrypt_credentials(file_path, fernet_key):
    f = Fernet(fernet_key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted = f.decrypt(encrypted_data)
    return json.loads(decrypted.decode())