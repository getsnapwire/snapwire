import os
import base64
import hashlib
from cryptography.fernet import Fernet


def _get_fernet():
    secret = os.environ.get("SESSION_SECRET", "snapwire-default-secret-change-me")
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def encrypt_api_key(api_key):
    f = _get_fernet()
    return f.encrypt(api_key.encode()).decode()


def decrypt_api_key(encrypted_key):
    f = _get_fernet()
    return f.decrypt(encrypted_key.encode()).decode()
