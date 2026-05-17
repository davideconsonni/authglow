"""AES-256-GCM encryption for sensitive fields (TOTP secrets, etc.)."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from authglow.core.config import get_settings

_PREFIX = "ag1:"
_INFO = b"authglow-totp-encryption-v1"
_AAD = b"authglow-totp"


def _derive_key() -> bytes:
    settings = get_settings()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_INFO,
    )
    return hkdf.derive(settings.secret_key.encode())


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
