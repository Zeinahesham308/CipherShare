import hashlib

def hash_password(password: str) -> str:
    """
    Hashes a password using SHA-256.

    Args:
        password (str): The plain-text password.

    Returns:
        str: The hashed password as a hexadecimal string.
    """
    return hashlib.sha256(password.encode()).hexdigest()