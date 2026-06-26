import base64
import os
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import bcrypt
# Passlib 1.7.4 compatibility monkeypatch for newer bcrypt versions
if not hasattr(bcrypt, "__about__"):
    class MockAbout:
        __version__ = getattr(bcrypt, "__version__", "4.0.0")
    bcrypt.__about__ = MockAbout()

from jose import jwt, JWTError
from passlib.context import CryptContext
from backend.app.core.config import settings

# CryptContext for password hashing utilities
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def _get_encryption_key() -> bytes:
    """Derives a secure 32-byte key from the configured encryption key."""
    return hashlib.sha256(settings.ENCRYPTION_KEY.encode()).digest()

def encrypt_text(text: str) -> str:
    """
    Encrypts clear text using AES-GCM-256.
    Returns a URL-safe Base64 encoded string containing nonce + ciphertext.
    """
    if not text:
        return text
    aesgcm = AESGCM(_get_encryption_key())
    nonce = os.urandom(12)  # Generates a standard 12-byte nonce
    encrypted_bytes = aesgcm.encrypt(nonce, text.encode("utf-8"), None)
    # Prefix the ciphertext with the nonce
    combined = nonce + encrypted_bytes
    return base64.urlsafe_b64encode(combined).decode("utf-8")

def decrypt_text(encrypted_text: str) -> str:
    """
    Decrypts a URL-safe Base64 encoded ciphertext string using AES-GCM-256.
    """
    if not encrypted_text:
        return encrypted_text
    try:
        combined = base64.urlsafe_b64decode(encrypted_text.encode("utf-8"))
        if len(combined) < 12:
            raise ValueError("Invalid cipher structure: too short.")
        nonce = combined[:12]
        ciphertext = combined[12:]
        aesgcm = AESGCM(_get_encryption_key())
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError("Decryption failed. Data might be corrupted or key mismatch.") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against its hashed representation."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashes a password using bcrypt."""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a JWT access token signed with HS256."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

def verify_access_token(token: str) -> Optional[dict]:
    """Decodes and validates a JWT access token. Returns decoded payload or None if invalid."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None
