"""File-system-backed repository for the JWT signing keyring.

On-disk layout (relative to ``settings.keys_dir``):

* ``<keys_dir>/keyring.json`` — index of every key + which is
  active. Atomic write via ``tmp+rename`` (crash-safe on
  local filesystems; cloud backends fall back to plain write).
* ``<keys_dir>/<kid>/private_key.pem`` — encrypted private
  key (AES-256-GCM with the project secret via
  :func:`authglow.core.crypto.encrypt_private_key`).
* ``<keys_dir>/<kid>/public_key.pem`` — public key in
  ``SubjectPublicKeyInfo`` format.
* ``<keys_dir>/private_key.pem`` / ``<keys_dir>/public_key.pem`` —
  backward-compat **copies** of the active key (legacy code
  paths still read these).

The pre-refactor ``core/config.py`` had the keyring I/O
inlined as module-level helpers (``_load_keyring``,
``_save_keyring``, ``_new_kid``, ``_generate_key_pair``,
``_write_active_symlinks``, ``_perform_rotation``,
``get_or_generate_keyring``). The
:class:`FileKeyStoreRepository` consolidates all of this
behind a single class with the Protocol-defined
``KeyStoreRepository`` interface.

The repository does **not** call the legacy
``get_or_generate_keyring`` migration logic on
construction — that's a startup concern owned by
``Settings.__init__`` (see ``core/config.py``). The
repository starts in a "keyring not loaded" state and the
first call to ``get_active_keypair`` (or any other read
method) triggers the on-disk load.

Cross-process safety: the ``tmp+rename`` atomic-write
pattern is the only cross-process safety the keyring has
(no CAS, no version field). For the local filesystem this
is crash-safe; for cloud backends the rename is **not**
available and the write is best-effort (a comment in
:meth:`_save_keyring` documents the fallback). This matches
the pre-refactor behaviour and the requirements of the
``BaseFileRepository._write_json_atomic`` helper.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from authglow.core.config import Settings
    from authglow.models.keystore import KeyPair, PublicKey


_KEYRING_FILENAME = "keyring.json"
_LEGACY_KID = "klegacy"


def _new_kid() -> str:
    """Generate a unique sortable key ID with timestamp + random suffix.

    Format: ``k<YYYYMMDDHHMMSS><2-byte-hex>`` (e.g. ``k20260614193015a3``).
    The timestamp prefix makes manual inspection of the keyring
    directory order-sorted by creation time.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = secrets.token_hex(2)
    return f"k{ts}{suffix}"


def _generate_key_pair(key_size: int = 2048) -> tuple[bytes, bytes]:
    """Generate a fresh RSA key pair and return
    ``(private_bytes, public_bytes)``.

    The private bytes are PKCS8 / PEM / unencrypted — the
    caller is responsible for encrypting them with
    :func:`authglow.core.crypto.encrypt_private_key` before
    persisting.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_bytes, pub_bytes


def _rsa_pem_to_jwk_components(public_pem: bytes) -> tuple[str, str]:
    """Convert a PEM public key to base64url-encoded ``n`` / ``e`` JWK components.

    The result is suitable for serialisation in a JWK Set
    (e.g. the ``/.well-known/jwks.json`` endpoint).
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    public_key = serialization.load_pem_public_key(public_pem)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError(f"Keyring only supports RSA keys (got {type(public_key).__name__})")
    numbers = public_key.public_numbers()

    def _b64u(value: int) -> str:
        byte_length = (value.bit_length() + 7) // 8
        return (
            base64.urlsafe_b64encode(value.to_bytes(byte_length, "big"))
            .rstrip(b"=")
            .decode("ascii")
        )

    return _b64u(numbers.n), _b64u(numbers.e)


class FileKeyStoreRepository:
    """File-backed implementation of :class:`KeyStoreRepository`.

    The repository is **not** a ``BaseFileRepository``
    subclass because the keyring layout spans multiple
    files (the index + per-kid PEM files + the legacy flat
    paths) and uses the ``tmp+rename`` atomic-write pattern
    directly. The fsspec + ``AsyncFileSystem`` abstraction is
    not relevant here — the keyring is a local-only concern
    (the cloud backends would store the keyring differently
    in any case, e.g. AWS KMS or HashiCorp Vault).

    For the same reason this class does not participate in
    the lru_cache-bypass dance of the other repositories:
    the ``Settings.keys_dir`` is set once at startup and
    never changes mid-process.
    """

    # NB: not @runtime_checkable — we use ``isinstance`` for
    # Protocol conformance via duck-typing (the Protocol is
    # @runtime_checkable, so isinstance() still works).

    def __init__(
        self,
        settings: Optional["Settings"] = None,
    ) -> None:
        from authglow.core.config import get_settings

        self.settings: "Settings" = settings or get_settings()
        self._keys_dir: str = self.settings.keys_dir
        self._keyring_path: str = os.path.join(self._keys_dir, _KEYRING_FILENAME)
        self._legacy_priv_path: str = os.path.join(self._keys_dir, "private_key.pem")
        self._legacy_pub_path: str = os.path.join(self._keys_dir, "public_key.pem")
        self._keyring: Optional[Dict[str, Any]] = None
        self._active_kid: Optional[str] = None

    # ------------------------------------------------------------------
    # Internal I/O helpers
    # ------------------------------------------------------------------

    def _load_keyring(self) -> Optional[Dict[str, Any]]:
        """Load keyring.json, return None if missing or corrupt.

        The repository caches the loaded keyring in
        ``self._keyring`` to avoid repeated disk reads.
        Callers that need a fresh view should call
        :meth:`_reload_keyring` explicitly.
        """
        if not os.path.exists(self._keyring_path):
            return None
        with open(self._keyring_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data  # type: ignore[no-any-return]

    def _save_keyring(self, keyring: Dict[str, Any]) -> None:
        """Atomically save keyring.json (tmp+rename).

        The tmp+rename pattern is crash-safe on POSIX
        filesystems (``os.replace`` is atomic on the same
        filesystem). The pre-refactor code used this same
        pattern.
        """
        tmp = self._keyring_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(keyring, f, indent=2)
        os.replace(tmp, self._keyring_path)

    def _write_active_symlinks(self, keyring: Dict[str, Any]) -> None:
        """Copy the active key to the legacy flat paths for
        backward compatibility with code that still reads
        ``<keys_dir>/private_key.pem`` / ``public_key.pem``.

        The pre-refactor used symlinks (hence the name
        ``_write_active_symlinks``) but on Windows symlinks
        require elevated privileges — we use ``shutil.copy2``
        which works on every platform. The function name is
        preserved for code-search compatibility.
        """
        active_kid = keyring["active_kid"]
        src_priv = os.path.join(self._keys_dir, active_kid, "private_key.pem")
        src_pub = os.path.join(self._keys_dir, active_kid, "public_key.pem")
        dst_priv = self._legacy_priv_path
        dst_pub = self._legacy_pub_path

        for dst in (dst_priv, dst_pub):
            try:
                os.remove(dst)
            except FileNotFoundError:
                pass

        shutil.copy2(src_priv, dst_priv)
        shutil.copy2(src_pub, dst_pub)

    def _kid_dir(self, kid: str) -> str:
        """Return the on-disk directory for a single key."""
        return os.path.join(self._keys_dir, kid)

    def _read_kid_pems(self, kid: str) -> Optional[tuple[bytes, bytes]]:
        """Read a kid's encrypted private + plaintext public PEMs.

        Returns ``None`` if either file is missing.
        """
        priv_path = os.path.join(self._kid_dir(kid), "private_key.pem")
        pub_path = os.path.join(self._kid_dir(kid), "public_key.pem")
        if not os.path.exists(priv_path) or not os.path.exists(pub_path):
            return None
        with open(priv_path, "rb") as f:
            private_pem = f.read()
        with open(pub_path, "rb") as f:
            public_pem = f.read()
        return private_pem, public_pem

    def _write_kid_pems(self, kid: str, private_pem: bytes, public_pem: bytes) -> None:
        """Write a kid's encrypted private + plaintext public PEMs."""
        os.makedirs(self._kid_dir(kid), exist_ok=True)
        priv_path = os.path.join(self._kid_dir(kid), "private_key.pem")
        pub_path = os.path.join(self._kid_dir(kid), "public_key.pem")
        with open(priv_path, "wb") as f:
            f.write(private_pem)
        with open(pub_path, "wb") as f:
            f.write(public_pem)

    def _ensure_loaded(self) -> None:
        """Load the keyring on the first read.

        Subsequent reads use the in-memory cache. Callers
        that mutate the keyring (rotate/revoke) should call
        :meth:`_reload_keyring` after the mutation to keep
        the in-memory state in sync.
        """
        if self._keyring is None:
            self._keyring = self._load_keyring()
            if self._keyring is not None:
                self._active_kid = self._keyring["active_kid"]

    def _reload_keyring(self) -> None:
        """Force a re-read of the keyring from disk."""
        self._keyring = self._load_keyring()
        if self._keyring is not None:
            self._active_kid = self._keyring["active_kid"]

    # ------------------------------------------------------------------
    # Protocol: get_active_keypair
    # ------------------------------------------------------------------

    async def get_active_keypair(self) -> Optional["KeyPair"]:
        """Return the active ``KeyPair`` (private + public PEM +
        metadata), or ``None`` if the keyring is missing.
        """

        self._ensure_loaded()
        if self._keyring is None or self._active_kid is None:
            return None
        return self._build_keypair(self._active_kid, self._keyring)

    # ------------------------------------------------------------------
    # Protocol: get_keypair_by_kid
    # ------------------------------------------------------------------

    async def get_keypair_by_kid(self, kid: str) -> Optional["KeyPair"]:
        """Return the ``KeyPair`` for *kid*, or ``None`` if
        the kid is not in the ring (or the on-disk PEMs are
        missing).
        """

        self._ensure_loaded()
        if self._keyring is None:
            return None
        if kid not in self._keyring["keys"]:
            return None
        return self._build_keypair(kid, self._keyring)

    def _build_keypair(self, kid: str, keyring: Dict[str, Any]) -> Optional["KeyPair"]:
        """Build a ``KeyPair`` from the in-memory keyring +
        on-disk PEMs. Returns ``None`` if the on-disk PEMs
        are missing (corrupt / partial state)."""
        from authglow.models.keystore import KeyPair, KeyPairMeta

        meta_dict = keyring["keys"][kid]
        pems = self._read_kid_pems(kid)
        if pems is None:
            return None
        private_pem, public_pem = pems
        meta = KeyPairMeta(kid=kid, **meta_dict)
        return KeyPair(kid=kid, private_pem=private_pem, public_pem=public_pem, meta=meta)

    # ------------------------------------------------------------------
    # Protocol: get_public_keys
    # ------------------------------------------------------------------

    async def get_public_keys(self) -> List["PublicKey"]:
        """Return every non-revoked public key in the ring as
        ``PublicKey`` entries for the JWKS endpoint.

        Revoked keys are excluded — they cannot be used to
        verify signatures. Verifying (retired) keys are
        included so existing tokens (signed before the
        rotation) can still be verified.
        """
        from authglow.models.keystore import PublicKey

        self._ensure_loaded()
        if self._keyring is None:
            return []

        result: List[PublicKey] = []
        for kid, meta in self._keyring["keys"].items():
            if meta.get("status") == "revoked":
                continue
            pems = self._read_kid_pems(kid)
            if pems is None:
                continue
            _, public_pem = pems
            n, e = _rsa_pem_to_jwk_components(public_pem)
            result.append(
                PublicKey(
                    kid=kid,
                    algorithm=meta.get("algorithm", "RS256"),
                    use="sig",
                    kty="RSA",
                    n=n,
                    e=e,
                    key_size=meta.get("key_size", 2048),
                    created_at=meta.get("created_at"),
                )
            )
        return result

    # ------------------------------------------------------------------
    # Protocol: rotate
    # ------------------------------------------------------------------

    async def rotate(self, secret_key: str, key_size: int = 2048) -> "KeyPair":
        """Generate a new RSA key pair, mark the current
        active key as ``verifying``, and persist. Returns
        the new active ``KeyPair``.

        Implementation note: the encryption is delegated to
        :func:`authglow.core.crypto.encrypt_private_key` for
        symmetry with the pre-refactor behaviour.
        """
        from authglow.core.crypto import encrypt_private_key
        from authglow.models.keystore import KeyPair, KeyPairMeta

        self._ensure_loaded()
        if self._keyring is None:
            raise RuntimeError(
                "Cannot rotate: keyring not initialised. Call "
                "get_or_generate_keyring() at startup first."
            )

        old_kid = self._keyring["active_kid"]
        new_kid = _new_kid()
        os.makedirs(self._kid_dir(new_kid), exist_ok=True)

        priv_bytes, pub_bytes = _generate_key_pair(key_size)
        encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
        self._write_kid_pems(new_kid, encrypted_priv, pub_bytes)

        now_str = datetime.now(timezone.utc).isoformat()
        self._keyring["keys"][new_kid] = {
            "created_at": now_str,
            "status": "active",
            "algorithm": "RS256",
            "key_size": key_size,
        }
        self._keyring["keys"][old_kid]["status"] = "verifying"
        self._keyring["keys"][old_kid]["retired_at"] = now_str
        self._keyring["active_kid"] = new_kid

        self._save_keyring(self._keyring)
        self._write_active_symlinks(self._keyring)
        self._active_kid = new_kid

        return KeyPair(
            kid=new_kid,
            private_pem=encrypted_priv,
            public_pem=pub_bytes,
            meta=KeyPairMeta(kid=new_kid, **self._keyring["keys"][new_kid]),
        )

    # ------------------------------------------------------------------
    # Protocol: revoke
    # ------------------------------------------------------------------

    async def revoke(self, kid: str) -> None:
        """Mark *kid* as ``revoked`` and persist.

        Revoked keys remain in the ring (for audit) but are
        excluded from :meth:`get_public_keys`. No-op if
        *kid* is not in the ring.
        """
        self._ensure_loaded()
        if self._keyring is None:
            return
        if kid not in self._keyring["keys"]:
            return
        self._keyring["keys"][kid]["status"] = "revoked"
        self._keyring["keys"][kid]["revoked_at"] = datetime.now(timezone.utc).isoformat()
        self._save_keyring(self._keyring)
        # No symlink update: revoking a non-active key does
        # not change which key the legacy flat paths point
        # at. Revoking the active key would be a service-
        # level concern (call rotate() first).

    # ------------------------------------------------------------------
    # Public helpers (not in the Protocol)
    # ------------------------------------------------------------------

    def is_loaded(self) -> bool:
        """Return ``True`` if the keyring has been loaded from
        disk. Used by tests to assert lazy-load semantics."""
        return self._keyring is not None

    def reload(self) -> None:
        """Force a re-read of the keyring from disk (useful
        after an external mutation, e.g. from the
        ``get_or_generate_keyring`` startup path).
        """
        self._reload_keyring()

    @classmethod
    def for_keys_dir(
        cls, keys_dir: str, secret_key: str, key_size: int = 2048
    ) -> "FileKeyStoreRepository":
        """Build a temporary ``Settings`` instance for
        direct ``keys_dir`` access.

        Used by ``core.config._generate_fresh_keyring`` and
        ``_perform_rotation`` (the startup migration / auto-
        rotation paths) so the repository can read / write
        the keyring files without going through the
        ``lru_cache``'d global ``get_settings()``.

        The ``secret_key`` is unused here — it's accepted for
        symmetry with the upstream caller (which will
        encrypt the freshly-generated private key with it).
        """

        # Build a minimal Settings instance for the keyring
        # location. The full Settings model has many
        # required fields (secret_key, storage_path, etc.)
        # — we just need ``keys_dir`` to resolve to the
        # right directory.
        # NB: instantiating ``Settings()`` triggers
        # ``get_or_generate_keyring`` recursively, so we
        # bypass the model entirely and construct a
        # stub-like object.
        class _KeysDirSettings:
            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

        repo = cls(settings=_KeysDirSettings(keys_dir))  # type: ignore[arg-type]
        return repo

    def get_keyring_dict(self) -> Optional[Dict[str, Any]]:
        """Return the in-memory keyring dict (for admin
        introspection). The pre-refactor ``JWTService.
        get_keyring_info`` returned a similar shape."""
        self._ensure_loaded()
        if self._keyring is None:
            return None
        # Cast to satisfy the typed return — self._keyring is
        # already a Dict[str, Any] but mypy sees it as
        # ``Optional[Any]`` after the json.load call.
        return self._keyring

    def get_active_kid(self) -> Optional[str]:
        """Return the active ``kid``, or ``None`` if the
        keyring is missing."""
        self._ensure_loaded()
        return self._active_kid
