# app/services/secure_store.py
import os
import base64
from cryptography.fernet import Fernet

_key = os.environ.get("TOKEN_ENC_KEY")
fernet = Fernet(base64.urlsafe_b64encode(_key.encode()[:32])) if _key else None

def encrypt(s: str) -> str:
    """문자열을 암호화합니다."""
    return fernet.encrypt(s.encode()).decode() if fernet else s

def decrypt(s: str) -> str:
    """암호화된 문자열을 복호화합니다."""
    return fernet.decrypt(s.encode()).decode() if (fernet and s) else s
