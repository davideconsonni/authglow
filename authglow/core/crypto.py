"""AES-256-GCM encryption for sensitive fields (TOTP secrets, RSA keys, etc.)."""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from authglow.core.config import get_settings

_PREFIX = "ag1:"
_INFO = b"authglow-totp-encryption-v1"
_AAD = b"authglow-totp"

_KEY_PREFIX = "agk1:"
_KEY_INFO = b"authglow-key-encryption-v1"
_KEY_AAD = b"authglow-private-key"


def _derive_key(info: bytes = _INFO) -> bytes:
    settings = get_settings()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
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


def encrypt_private_key(plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    key = _derive_key(info=_KEY_INFO)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, _KEY_AAD)
    return _KEY_PREFIX.encode() + base64.b64encode(iv + ciphertext)


def decrypt_private_key(encrypted: bytes) -> bytes:
    if not encrypted.startswith(_KEY_PREFIX.encode()):
        return encrypted
    raw = base64.b64decode(encrypted[len(_KEY_PREFIX) :])
    iv = raw[:12]
    ciphertext = raw[12:]
    key = _derive_key(info=_KEY_INFO)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, _KEY_AAD)
