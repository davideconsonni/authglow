"""AES-256-GCM encryption for sensitive fields (TOTP secrets, RSA keys, user PII)."""

import base64
import hashlib
import hmac
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PREFIX = "ag1:"
_INFO = b"authglow-totp-encryption-v1"
_AAD = b"authglow-totp"

_KEY_PREFIX = "agk1:"
_KEY_INFO = b"authglow-key-encryption-v1"
_KEY_AAD = b"authglow-private-key"

_USER_INFO = b"authglow-user-field-v1"
_FEDERATION_STATE_INFO = b"authglow-federation-state-v1"


def _resolve_secret_key(secret_key: Optional[str] = None) -> str:
    if secret_key is not None:
        return secret_key
    from authglow.core.config import get_settings

    return get_settings().secret_key


def _derive_key(secret_key: Optional[str] = None, info: bytes = _INFO) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    return hkdf.derive(_resolve_secret_key(secret_key).encode())


def derive_federation_state_key(secret_key: Optional[str] = None) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_FEDERATION_STATE_INFO,
    )
    return hkdf.derive(_resolve_secret_key(secret_key).encode())


def encrypt_totp_secret(plaintext: str) -> str:
    if not plaintext:
        return plaintext
    iv = os.urandom(12)
    key = _derive_key()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), _AAD)
    return _PREFIX + base64.b64encode(iv + ciphertext).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith(_PREFIX):
        return ciphertext
    raw = base64.b64decode(ciphertext[len(_PREFIX) :])
    iv = raw[:12]
    encrypted = raw[12:]
    key = _derive_key()
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, encrypted, _AAD)
    return plaintext.decode()


def encrypt_private_key(plaintext: bytes, secret_key: Optional[str] = None) -> bytes:
    iv = os.urandom(12)
    key = _derive_key(secret_key=secret_key, info=_KEY_INFO)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, _KEY_AAD)
    return _KEY_PREFIX.encode() + base64.b64encode(iv + ciphertext)


def decrypt_private_key(encrypted: bytes, secret_key: Optional[str] = None) -> bytes:
    if not encrypted.startswith(_KEY_PREFIX.encode()):
        return encrypted
    raw = base64.b64decode(encrypted[len(_KEY_PREFIX) :])
    iv = raw[:12]
    ciphertext = raw[12:]
    key = _derive_key(secret_key=secret_key, info=_KEY_INFO)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, _KEY_AAD)


def encrypt_field(plaintext: str) -> str:
    """Encrypt a single PII field (email, name, phone) using AES-256-GCM.

    Uses the same ``ag1:`` prefix and HKDF as TOTP secrets for consistency.
    """
    if not plaintext:
        return plaintext
    iv = os.urandom(12)
    key = _derive_key(info=_USER_INFO)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), _AAD)
    return _PREFIX + base64.b64encode(iv + ciphertext).decode()


def decrypt_field(ciphertext: str) -> str:
    """Decrypt a field encrypted with ``encrypt_field``.

    Automatically handles plaintext (backward-compatible migration path).
    """
    if not ciphertext or not ciphertext.startswith(_PREFIX):
        return ciphertext
    raw = base64.b64decode(ciphertext[len(_PREFIX) :])
    iv = raw[:12]
    encrypted = raw[12:]
    key = _derive_key(info=_USER_INFO)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, encrypted, _AAD).decode()


def hash_index_key(email_lower: str) -> str:
    """Compute HMAC-SHA256 index key from an email address.

    Used as the lookup key in the email index so that plaintext
    email addresses are never persisted to disk.
    """
    secret = _resolve_secret_key().encode()
    return hmac.new(secret, email_lower.encode(), hashlib.sha256).hexdigest()
