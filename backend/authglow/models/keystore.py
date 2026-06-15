"""KeyStore domain models — RSA key ring with rotation and revocation.

The keyring is a collection of RSA key pairs (one per
``kid`` = key ID) used to sign and verify JWTs. The active
``kid`` is the one used for new signatures; older kids remain
in the ring during a ``verifying`` window (so existing tokens
can still be verified) and are eventually ``revoked``.

The on-disk layout (managed by
:class:`FileKeyStoreRepository`) is:

* ``<keys_dir>/keyring.json`` — index of every key + which is
  active. Atomic write via ``tmp+rename``.
* ``<keys_dir>/<kid>/private_key.pem`` — encrypted private key.
* ``<keys_dir>/<kid>/public_key.pem`` — public key in
  ``SubjectPublicKeyInfo`` format.
* ``<keys_dir>/private_key.pem`` / ``<keys_dir>/public_key.pem`` —
  backward-compat symlinks/copies of the **active** key, used
  by legacy code paths.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class KeyPairMeta(BaseModel):
    """Metadata for a single key in the keyring.

    Matches the on-disk representation in ``keyring.json``
    under the ``keys`` dict, keyed by ``kid``.
    """

    kid: str
    created_at: str  # ISO-8601
    status: str  # "active" | "verifying" | "revoked"
    algorithm: str = "RS256"
    key_size: int = 2048
    retired_at: Optional[str] = None
    revoked_at: Optional[str] = None


class KeyPair(BaseModel):
    """An RSA key pair (private + public) with its metadata.

    The ``private_pem`` is the **encrypted** PEM (encrypted at
    rest with the project secret via
    :func:`authglow.core.crypto.encrypt_private_key`); the
    ``public_pem`` is the standard ``SubjectPublicKeyInfo``
    PEM. The repository is responsible for the
    encryption/decryption round-trip.
    """

    kid: str
    private_pem: bytes
    public_pem: bytes
    meta: KeyPairMeta


class PublicKey(BaseModel):
    """A public key entry for the JWKS endpoint.

    Includes the standard JWK fields (``kty``, ``alg``,
    ``use``, ``kid``) plus the ``n`` / ``e`` base64url-encoded
    RSA modulus / exponent that the JWKS consumer needs to
    verify signatures. The ``key_size`` and ``created_at`` are
    metadata fields for admin introspection, not part of the
    JWK spec.
    """

    kid: str
    algorithm: str = "RS256"
    use: str = "sig"
    kty: str = "RSA"
    n: str  # base64url-encoded RSA modulus
    e: str  # base64url-encoded RSA exponent
    key_size: int = 2048
    created_at: Optional[str] = None


class KeyringInfo(BaseModel):
    """Snapshot of the keyring for admin introspection.

    Returned by the ``GET /admin/jwks`` (or similar) endpoint
    to expose the active kid + per-key metadata without
    revealing the private keys.
    """

    active_kid: str
    keys: List[KeyPairMeta]
    last_updated: Optional[datetime] = None


__all__ = ["KeyPair", "KeyPairMeta", "KeyringInfo", "PublicKey"]
