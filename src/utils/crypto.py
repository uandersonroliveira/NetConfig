import os
import base64
import hashlib
from pathlib import Path
from cryptography.fernet import Fernet


def _get_machine_key() -> bytes:
    """Generate a machine-specific key for encryption."""
    key_file = Path(__file__).parent.parent.parent / "data" / ".key"

    if key_file.exists():
        return key_file.read_bytes()

    key_file.parent.mkdir(parents=True, exist_ok=True)

    key = Fernet.generate_key()
    key_file.write_bytes(key)

    return key


def _get_fernet() -> Fernet:
    """Get Fernet instance with machine key."""
    key = _get_machine_key()
    return Fernet(key)


def encrypt_password(password: str) -> str:
    """Encrypt a password and return base64-encoded ciphertext."""
    fernet = _get_fernet()
    encrypted = fernet.encrypt(password.encode('utf-8'))
    return encrypted.decode('utf-8')


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a base64-encoded ciphertext and return the password."""
    fernet = _get_fernet()
    decrypted = fernet.decrypt(encrypted_password.encode('utf-8'))
    return decrypted.decode('utf-8')
