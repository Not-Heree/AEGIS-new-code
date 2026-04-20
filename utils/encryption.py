"""
Encryption utility for sensitive data storage.
Uses Fernet (symmetric encryption) from cryptography library.
"""

import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


# Generate encryption key from Flask SECRET_KEY
def _get_encryption_key():
    """
    Derive encryption key from Flask SECRET_KEY.
    Uses PBKDF2 for key derivation.
    """
    from config import Config

    secret = Config.SECRET_KEY.encode()
    salt = b'easm_tool_salt_v1'  # Static salt (OK for app-wide encryption)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(secret))
    return key


# Global cipher instance
_cipher = Fernet(_get_encryption_key())


def encrypt_value(plaintext: str) -> str:
    """
    Encrypt a string value.

    Args:
        plaintext: String to encrypt

    Returns:
        Base64-encoded encrypted string
    """
    if not plaintext:
        return ""

    encrypted = _cipher.encrypt(plaintext.encode())
    return encrypted.decode()


def decrypt_value(ciphertext: str) -> str:
    """
    Decrypt an encrypted string.

    Args:
        ciphertext: Encrypted string to decrypt

    Returns:
        Decrypted plaintext string
    """
    if not ciphertext:
        return ""

    try:
        decrypted = _cipher.decrypt(ciphertext.encode())
        return decrypted.decode()
    except Exception:
        return ""


def mask_api_key(key: str) -> str:
    """
    Mask API key for display (show first/last 4 chars).

    Args:
        key: API key to mask

    Returns:
        Masked string like "sk-1234...5678"
    """
    if not key or len(key) < 8:
        return "****"

    return f"{key[:4]}...{key[-4:]}"