"""AES-256-GCM encryption for sensitive fields (TOTP secrets, RSA keys, user PII)."""

import base64
import functools
import hashlib
import hmac
import os
from typing import Iterable, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_PREFIX = "ag1:"
_INFO = b"authglow-totp-encryption-v1"

# VAPT-041: TOTP-secret AAD is now versioned to align with the
# other envelopes in this module. The legacy unversioned AAD
# is kept as a decryption-only fallback so existing on-disk
# ciphertexts (encrypted before this change) continue to
# decrypt transparently. The encryption path always uses the
# versioned AAD.
_AAD = b"authglow-totp-v1"
_AAD_LEGACY = b"authglow-totp"

_KEY_PREFIX = "agk1:"
_KEY_INFO = b"authglow-key-encryption-v1"

# VAPT-041: same pattern for the RSA-private-key AAD. Legacy
# value kept for backward-compatible decryption of any
# pre-versioning ciphertext (the keyring was added in Fase 20
# with the unversioned AAD and may still be on disk in
# long-lived deployments).
_KEY_AAD = b"authglow-private-key-v1"
_KEY_AAD_LEGACY = b"authglow-private-key"

_USER_INFO = b"authglow-user-field-v1"
_FEDERATION_STATE_INFO = b"authglow-federation-state-v1"

# T.2: encryption context for the server-side symmetric key used to verify
# HS256 client_assertion JWTs (``token_endpoint_auth_method=client_secret_jwt``).
# Distinct AAD/info from TOTP/private-key encryption so a rotation of one
# context does not invalidate the others.
_CLIENT_JWT_KEY_PREFIX = "agcj1:"
_CLIENT_JWT_KEY_INFO = b"authglow-client-jwt-key-encryption-v1"
_CLIENT_JWT_KEY_AAD = b"authglow-client-jwt-key"

# Sentinel used as the lru_cache key for the "no explicit secret_key"
# call site — None is not hashable. The sentinel is never a real
# ``SECRET_KEY`` value (those are 48-char base64url strings from
# ``secrets.token_urlsafe``).
_DEFAULT_SECRET_SENTINEL = "__default__"


def _resolve_secret_key(secret_key: Optional[str] = None) -> str:
    if secret_key is not None:
        return secret_key
    from authglow.core.config import get_settings

    return get_settings().secret_key


@functools.lru_cache(maxsize=8)
def _derive_key(secret_key: str = _DEFAULT_SECRET_SENTINEL, info: bytes = _INFO) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=info,
    )
    effective_secret = (
        _resolve_secret_key() if secret_key == _DEFAULT_SECRET_SENTINEL else secret_key
    )
    return hkdf.derive(effective_secret.encode())


def derive_federation_state_key(secret_key: Optional[str] = None) -> bytes:
    return _derive_key(
        secret_key=secret_key if secret_key is not None else _DEFAULT_SECRET_SENTINEL,
        info=_FEDERATION_STATE_INFO,
    )


def _try_decrypt_with_aads(iv: bytes, encrypted: bytes, aads: Iterable[bytes], key: bytes) -> bytes:
    """VAPT-041: try each AAD candidate and return the first successful decrypt.

    Used by the AAD-versioned helpers (``decrypt_totp_secret``,
    ``decrypt_private_key``) so a deployment that has a mix of
    pre-versioning and post-versioning ciphertexts on disk can
    read both. ``InvalidTag`` is swallowed because every
    AES-GCM tag-mismatch is just "wrong AAD" in this context
    (the key is the same, the IV is the same, the ciphertext
    is the same — only the AAD varies).

    If every candidate fails, the last exception is re-raised
    so the caller can log / surface the original error.
    """
    last_exc: Optional[Exception] = None
    for aad in aads:
        try:
            return AESGCM(key).decrypt(iv, encrypted, aad)
        except InvalidTag as exc:
            last_exc = exc
    # No AAD matched — surface the underlying AES-GCM error
    # so the caller can treat it as a tamper / corruption
    # signal rather than a "version not supported" error.
    assert last_exc is not None  # the loop above runs at least once
    raise last_exc


def encrypt_totp_secret(plaintext: str) -> str:
    """Encrypt a TOTP secret with the versioned AAD (VAPT-041).

    Always uses ``_AAD`` (``b"authglow-totp-v1"``). The
    pre-versioning AAD is decrypt-only.
    """
    if not plaintext:
        return plaintext
    iv = os.urandom(12)
    key = _derive_key()
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), _AAD)
    return _PREFIX + base64.b64encode(iv + ciphertext).decode()


def decrypt_totp_secret(ciphertext: str) -> str:
    """Decrypt a TOTP secret, tolerating the legacy AAD (VAPT-041).

    Order matters: the versioned AAD is tried first because
    every freshly-written ciphertext uses it, so the happy
    path stays single-try. The legacy AAD is a fallback for
    pre-VAPT-041 on-disk data only.
    """
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith(_PREFIX):
        return ciphertext
    raw = base64.b64decode(ciphertext[len(_PREFIX) :])
    iv = raw[:12]
    encrypted = raw[12:]
    key = _derive_key()
    plaintext_bytes = _try_decrypt_with_aads(iv, encrypted, (_AAD, _AAD_LEGACY), key)
    return plaintext_bytes.decode()


def encrypt_private_key(plaintext: bytes, secret_key: Optional[str] = None) -> bytes:
    """Encrypt an RSA private key with the versioned AAD (VAPT-041).

    Always uses ``_KEY_AAD`` (``b"authglow-private-key-v1"``).
    The pre-versioning AAD is decrypt-only.
    """
    iv = os.urandom(12)
    key = _derive_key(
        secret_key=secret_key if secret_key is not None else _DEFAULT_SECRET_SENTINEL,
        info=_KEY_INFO,
    )
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, _KEY_AAD)
    return _KEY_PREFIX.encode() + base64.b64encode(iv + ciphertext)


def decrypt_private_key(encrypted: bytes, secret_key: Optional[str] = None) -> bytes:
    """Decrypt an RSA private key, tolerating the legacy AAD (VAPT-041).

    Mirrors :func:`decrypt_totp_secret` — the versioned AAD is
    tried first (the hot path), the legacy AAD is a fallback
    for pre-versioning keyring data.
    """
    if not encrypted.startswith(_KEY_PREFIX.encode()):
        return encrypted
    raw = base64.b64decode(encrypted[len(_KEY_PREFIX) :])
    iv = raw[:12]
    ciphertext = raw[12:]
    key = _derive_key(
        secret_key=secret_key if secret_key is not None else _DEFAULT_SECRET_SENTINEL,
        info=_KEY_INFO,
    )
    return _try_decrypt_with_aads(iv, ciphertext, (_KEY_AAD, _KEY_AAD_LEGACY), key)


def encrypt_index_value(plaintext: str, secret_key: Optional[str] = None) -> str:
    """Encrypt an index-file payload using the private-key envelope (VAPT-040).

    The refresh-token ``id_index``/``active_index`` and the API-key
    ``prefix_index`` used to store live ``token_id``s and ``key_id``s
    in plaintext, so an attacker with read access to the storage
    directory could enumerate every active session. This helper
    encrypts those index payloads with the same AES-256-GCM envelope
    (``agk1:`` prefix, ``_KEY_INFO`` / ``_KEY_AAD``) used for the
    RSA keyring, so a single ``Settings.secret_key`` rotation
    invalidates indexes and keys together.

    ``plaintext`` is typically a JSON string (the serialized
    index dict/list). The encryption is authenticated (GCM tag)
    so any tamper on disk is detected at decrypt time.
    """
    if not plaintext:
        return plaintext
    iv = os.urandom(12)
    key = _derive_key(
        secret_key=secret_key if secret_key is not None else _DEFAULT_SECRET_SENTINEL,
        info=_KEY_INFO,
    )
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), _KEY_AAD)
    return _KEY_PREFIX + base64.b64encode(iv + ciphertext).decode()


def decrypt_index_value(ciphertext: str, secret_key: Optional[str] = None) -> str:
    """Decrypt an index-file payload produced by :func:`encrypt_index_value`.

    Tolerates a plaintext payload (missing ``agk1:`` prefix) for
    backward compatibility with pre-VAPT-040 deployments — the
    caller is expected to re-encrypt on the next write so the
    legacy plaintext is replaced transparently.
    """
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith(_KEY_PREFIX):
        # Migration: pre-VAPT-040 plaintext index. Return as-is
        # so the caller can read the legacy data; the next
        # ``encrypt_index_value`` call will rewrite it encrypted.
        return ciphertext
    raw = base64.b64decode(ciphertext[len(_KEY_PREFIX) :])
    iv = raw[:12]
    encrypted = raw[12:]
    key = _derive_key(
        secret_key=secret_key if secret_key is not None else _DEFAULT_SECRET_SENTINEL,
        info=_KEY_INFO,
    )
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, encrypted, _KEY_AAD).decode("utf-8")


def hmac_index_filename(value: str, secret_key: Optional[str] = None) -> str:
    """Compute an HMAC-SHA256 pseudonym for use as a filename (VAPT-040).

    The token-blacklist directory stores one JSON file per
    revoked JTI. The pre-fix layout used ``<jti>.json`` as the
    filename, which leaked the JTI to anyone with directory
    read access. This helper returns a deterministic
    64-char hex digest that is safe to expose as a filename:
    an attacker who lists the directory sees only opaque
    pseudonyms, while the service can still look up the right
    file by computing the HMAC of the JTI it wants to check.

    The returned value is **not** prefixed with the
    ``agk1:`` envelope marker — the prefix is reserved for
    *content* envelopes, and the file name only needs to be a
    portable identifier on every supported filesystem
    (notably Windows, where ``:`` is not a valid filename
    character). Legacy plaintext JTI filenames are filtered
    out by length/character-set checks at the repository
    layer (``_is_legacy_filename``).

    Uses the private-key context so a ``Settings.secret_key``
    rotation invalidates the blacklist in lockstep with the
    keyring.
    """
    if not value:
        raise ValueError("hmac_index_filename: value must be non-empty")
    effective = _resolve_secret_key() if secret_key is None else secret_key
    return hmac.new(effective.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


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


def encrypt_client_jwt_key(plaintext: str) -> str:
    """Encrypt the symmetric key used for HS256 client_assertion JWTs.

    T.2 / FAPI 2.0: the server stores a per-client HMAC key in
    encrypted form. Rotating ``Settings.secret_key`` invalidates all
    stored client JWT keys (acceptable — the operator can re-issue
    keys via the admin rotation flow).
    """
    if not plaintext:
        return plaintext
    iv = os.urandom(12)
    key = _derive_key(info=_CLIENT_JWT_KEY_INFO)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode(), _CLIENT_JWT_KEY_AAD)
    return _CLIENT_JWT_KEY_PREFIX + base64.b64encode(iv + ciphertext).decode()


def decrypt_client_jwt_key(ciphertext: str) -> str:
    """Decrypt a client JWT key previously encrypted with ``encrypt_client_jwt_key``.

    Returns the input unchanged if it does not start with the expected
    prefix — the persistence layer treats an empty/missing value as
    "no key configured" and we never want to silently fall back to a
    plaintext key (it would be a config error).
    """
    if not ciphertext:
        return ciphertext
    if not ciphertext.startswith(_CLIENT_JWT_KEY_PREFIX):
        raise ValueError(
            "Client JWT key ciphertext is malformed (missing agcj1: prefix). "
            "This usually indicates the data was written with a different "
            "encryption context — re-issue the key via the admin rotation flow."
        )
    raw = base64.b64decode(ciphertext[len(_CLIENT_JWT_KEY_PREFIX) :])
    iv = raw[:12]
    encrypted = raw[12:]
    key = _derive_key(info=_CLIENT_JWT_KEY_INFO)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, encrypted, _CLIENT_JWT_KEY_AAD).decode()


@functools.lru_cache(maxsize=8)
def hash_index_key(email_lower: str) -> str:
    """Compute HMAC-SHA256 index key from an email address.

    Used as the lookup key in the email index so that plaintext
    email addresses are never persisted to disk.
    """
    secret = _resolve_secret_key().encode()
    return hmac.new(secret, email_lower.encode(), hashlib.sha256).hexdigest()


@functools.lru_cache(maxsize=8)
def reset_code_lookup_key(secret_key: str, code: str) -> str:
    """Compute the HMAC-SHA256 lookup key for a password-reset code.

    VAPT-022: the same ``PasswordResetToken`` record is indexed by
    both ``token_lookup`` (HMAC of the bearer token) and the
    ``code_lookup`` (HMAC of the human-friendly reset code). The
    code is normalised to upper-case and stripped of whitespace so
    user input variants (``abcd-efgh-jklm``) match the stored
    value.

    Exposed as a free function (taking ``secret_key`` explicitly)
    so the ``FilePasswordResetRepository`` can call it from its
    dual-mirror write without importing from the service layer.
    """
    normalised = code.strip().upper().replace(" ", "").replace("\t", "")
    return hmac.new(secret_key.encode(), normalised.encode(), hashlib.sha256).hexdigest()


@functools.lru_cache(maxsize=8)
def verification_code_lookup_key(secret_key: str, code: str) -> str:
    """Compute the HMAC-SHA256 lookup key for an email-verification code.

    Mirrors :func:`reset_code_lookup_key` for the email-verification
    flow. The code is normalised to upper-case and stripped of
    whitespace so user input variants (``abcd-efgh-jkmn``) match the
    stored value.

    The verification flow uses the human-friendly ``XXXX-XXXX-XXXX``
    code (VAPT-022 alignment) rather than a long opaque bearer
    token — the file repo stores the plaintext in the JSON body
    and uses this HMAC as the dual-mirror filename.
    """
    normalised = code.strip().upper().replace(" ", "").replace("\t", "")
    return hmac.new(secret_key.encode(), normalised.encode(), hashlib.sha256).hexdigest()
