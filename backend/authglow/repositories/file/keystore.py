"""File-system-backed repository for the JWT signing keyring.

On-disk layout (relative to ``settings.keys_dir``):

* ``<keys_dir>/keyring.json`` — index of every key + which is
  active. Atomic write via ``_write_json_versioned`` (CAS via the
  ``_version`` field; tmp+rename on local filesystems, optimistic
  concurrency on S3/GCS/ABFS).
* ``<keys_dir>/<kid>/private_key.pem`` — encrypted private
  key (AES-256-GCM with the project secret via
  :func:`authglow.core.crypto.encrypt_private_key`).
* ``<keys_dir>/<kid>/public_key.pem`` — public key in
  ``SubjectPublicKeyInfo`` format.
* ``<keys_dir>/private_key.pem`` / ``<keys_dir>/public_key.pem`` —
  backward-compat **copies** of the active key (legacy code
  paths still read these).

The class is a ``BaseFileRepository`` subclass with a custom
``root_dir=settings.keys_dir`` so the keyring rides on the same
fsspec layer as every other entity and honours
``Settings.storage_backend``. Atomicity is guaranteed by the
``_version`` field in ``keyring.json``: every ``rotate`` / ``revoke``
reads the current version, increments it, and writes back via
``_write_json_versioned`` which raises ``ConcurrentWriteError`` on
a version mismatch.

Cross-process safety:

* Local filesystem: ``tmp+rename`` (POSIX atomic) wrapped in a
  version check.
* S3 / GCS / ABFS: optimistic concurrency via the fsspec
  implementation's native CAS (S3 conditional ``PutObject``,
  GCS ``generation`` match, ABFS lease). Concurrent writers
  (multiple instances rotating at once) get
  ``ConcurrentWriteError`` and the service layer retries.

The legacy ``_write_active_symlinks`` helper is renamed to
``_write_active_copies`` (the pre-refactor code used symlinks
on POSIX and copies on Windows; the function name survived
code-search compat). It is implemented in terms of
``AsyncFileSystem.read_bytes`` / ``write_bytes`` so it works on
every backend.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional, cast

from authglow.core.concurrency import ConcurrentWriteError
from authglow.repositories.file.base import BaseFileRepository

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


class FileKeyStoreRepository(BaseFileRepository):
    """File-backed implementation of :class:`KeyStoreRepository`.

    Inherits the fsspec / ``AsyncFileSystem`` plumbing from
    :class:`BaseFileRepository` and overrides the root directory
    to ``settings.keys_dir`` (the keyring lives outside
    ``storage_path`` by design — it's a separate secret). The
    ``_storage_path`` / ``_path`` / ``_afs`` machinery therefore
    works for ``keyring.json`` and per-kid PEMs without any
    subclass-specific fsspec code.

    Atomicity is provided by the ``_version`` field in
    ``keyring.json``: every write goes through
    ``_write_json_versioned`` which raises
    :class:`ConcurrentWriteError` on a version mismatch. Callers
    (the service layer) must catch and retry the read-modify-write
    loop on this error.

    For the lru_cache bypass pattern see :class:`BaseFileRepository`
    and :func:`get_keystore_repository` — the repository accepts
    an explicit ``settings=`` argument so tests and the startup
    path can route around the process-cached
    :func:`authglow.core.config.get_settings`.
    """

    _subdir = ""

    def __init__(self, settings: Optional["Settings"] = None) -> None:
        super().__init__(settings=settings, root_dir=self._resolve_root_dir(settings))
        self._keyring: Optional[Dict[str, Any]] = None
        self._active_kid: Optional[str] = None

    @staticmethod
    def _resolve_root_dir(settings: Optional["Settings"]) -> str:
        """Return the keys_dir from settings, falling back to get_settings()."""
        if settings is not None:
            return settings.keys_dir
        from authglow.core.config import get_settings

        return get_settings().keys_dir

    # ------------------------------------------------------------------
    # Path helpers (relative to the keys_dir root)
    # ------------------------------------------------------------------

    def _kid_dir(self, kid: str) -> str:
        """Return the on-disk directory for a single key (relative to root)."""
        return kid

    def _keyring_path(self) -> str:
        """Return the fsspec path to keyring.json."""
        return self._path(_KEYRING_FILENAME)

    def _legacy_priv_path(self) -> str:
        return self._path("private_key.pem")

    def _legacy_pub_path(self) -> str:
        return self._path("public_key.pem")

    def _kid_priv_path(self, kid: str) -> str:
        return self._path(f"{kid}/private_key.pem")

    def _kid_pub_path(self, kid: str) -> str:
        return self._path(f"{kid}/public_key.pem")

    # ------------------------------------------------------------------
    # Keyring I/O
    # ------------------------------------------------------------------

    async def _load_keyring(self) -> Optional[Dict[str, Any]]:
        """Load keyring.json via fsspec. Returns None if missing/corrupt.

        The repository caches the loaded keyring in
        ``self._keyring`` to avoid repeated reads. Callers that
        need a fresh view should call :meth:`_reload_keyring`
        explicitly.
        """
        if not await self._exists(self._keyring_path()):
            return None
        data, version = await self._read_json_versioned(self._keyring_path())
        if data is None:
            return None
        if version > 0:
            data["_version"] = version
        return cast(Optional[Dict[str, Any]], data)

    async def _save_keyring(self, keyring: Dict[str, Any]) -> None:
        """Atomically save keyring.json with CAS.

        The ``_version`` field is stripped from the input dict,
        re-computed, and re-attached so callers don't have to
        manage it. On a version mismatch (another instance
        rotated first) this raises :class:`ConcurrentWriteError`.
        """
        expected_version = int(keyring.get("_version", 0))
        payload = {k: v for k, v in keyring.items() if k != "_version"}
        await self._write_json_versioned(self._keyring_path(), payload, expected_version)
        # Update the in-memory version so the next save has the
        # right expected value.
        keyring["_version"] = expected_version + 1

    async def _write_active_copies(self, keyring: Dict[str, Any]) -> None:
        """Copy the active key to the legacy flat paths for
        backward compatibility with code that still reads
        ``<keys_dir>/private_key.pem`` / ``public_key.pem``.

        Implemented via :meth:`AsyncFileSystem.read_bytes` /
        :meth:`AsyncFileSystem.write_bytes` so it works on every
        fsspec backend (local, S3, GCS, ABFS). The pre-refactor
        used POSIX symlinks (hence the original name
        ``_write_active_symlinks``) but on Windows symlinks
        require elevated privileges — copies work everywhere.
        """
        active_kid = keyring["active_kid"]
        priv_src = self._kid_priv_path(active_kid)
        pub_src = self._kid_pub_path(active_kid)
        priv_dst = self._legacy_priv_path()
        pub_dst = self._legacy_pub_path()

        priv_bytes = await self._afs.read_bytes(priv_src)
        pub_bytes = await self._afs.read_bytes(pub_src)

        # Best-effort delete-then-write on the legacy paths.
        # On local this is rm(1)+write(2); on cloud this is
        # delete+put — the legacy files are backward-compat
        # mirrors, not security-critical, so a torn window is
        # acceptable.
        for dst in (priv_dst, pub_dst):
            await self._delete(dst)
        await self._afs.write_bytes(priv_dst, priv_bytes)
        await self._afs.write_bytes(pub_dst, pub_bytes)

    async def _read_kid_pems(self, kid: str) -> Optional[tuple[bytes, bytes]]:
        """Read a kid's encrypted private + plaintext public PEMs.

        Returns ``None`` if either file is missing.
        """
        priv_path = self._kid_priv_path(kid)
        pub_path = self._kid_pub_path(kid)
        if not (await self._exists(priv_path)) or not (await self._exists(pub_path)):
            return None
        private_pem = await self._afs.read_bytes(priv_path)
        public_pem = await self._afs.read_bytes(pub_path)
        return private_pem, public_pem

    async def _write_kid_pems(self, kid: str, private_pem: bytes, public_pem: bytes) -> None:
        """Write a kid's encrypted private + plaintext public PEMs."""
        kid_dir = self._path(self._kid_dir(kid))
        await self._afs.makedirs(kid_dir, exist_ok=True)
        await self._afs.write_bytes(self._kid_priv_path(kid), private_pem)
        await self._afs.write_bytes(self._kid_pub_path(kid), public_pem)

    async def _ensure_loaded(self) -> None:
        """Load the keyring on the first read.

        Subsequent reads use the in-memory cache. Callers
        that mutate the keyring (rotate/revoke) should call
        :meth:`_reload_keyring` after the mutation to keep
        the in-memory state in sync.
        """
        if self._keyring is None:
            self._keyring = await self._load_keyring()
            if self._keyring is not None:
                self._active_kid = self._keyring.get("active_kid")

    async def _reload_keyring(self) -> None:
        """Force a re-read of the keyring from disk (fsspec)."""
        self._keyring = await self._load_keyring()
        if self._keyring is not None:
            self._active_kid = self._keyring.get("active_kid")

    # ------------------------------------------------------------------
    # Protocol: get_active_keypair
    # ------------------------------------------------------------------

    async def get_active_keypair(self) -> Optional["KeyPair"]:
        """Return the active ``KeyPair`` (private + public PEM +
        metadata), or ``None`` if the keyring is missing.
        """

        await self._ensure_loaded()
        if self._keyring is None or self._active_kid is None:
            return None
        return await self._build_keypair(self._active_kid, self._keyring)

    # ------------------------------------------------------------------
    # Protocol: get_keypair_by_kid
    # ------------------------------------------------------------------

    async def get_keypair_by_kid(self, kid: str) -> Optional["KeyPair"]:
        """Return the ``KeyPair`` for *kid*, or ``None`` if
        the kid is not in the ring (or the on-disk PEMs are
        missing).
        """

        await self._ensure_loaded()
        if self._keyring is None:
            return None
        if kid not in self._keyring["keys"]:
            return None
        return await self._build_keypair(kid, self._keyring)

    async def _build_keypair(self, kid: str, keyring: Dict[str, Any]) -> Optional["KeyPair"]:
        """Build a ``KeyPair`` from the in-memory keyring +
        on-disk PEMs. Returns ``None`` if the on-disk PEMs
        are missing (corrupt / partial state)."""
        from authglow.models.keystore import KeyPair, KeyPairMeta

        meta_dict = keyring["keys"][kid]
        pems = await self._read_kid_pems(kid)
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

        await self._ensure_loaded()
        if self._keyring is None:
            return []

        result: List[PublicKey] = []
        for kid, meta in self._keyring["keys"].items():
            if meta.get("status") == "revoked":
                continue
            pems = await self._read_kid_pems(kid)
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
        symmetry with the pre-refactor behaviour. The write
        goes through ``_write_json_versioned`` for cloud
        atomicity — a concurrent rotator on another instance
        gets :class:`ConcurrentWriteError` and the service
        layer retries.
        """
        from authglow.core.crypto import encrypt_private_key
        from authglow.models.keystore import KeyPair, KeyPairMeta

        await self._ensure_loaded()
        if self._keyring is None:
            raise RuntimeError(
                "Cannot rotate: keyring not initialised. Call "
                "get_or_generate_keyring() at startup first."
            )

        old_kid = self._keyring["active_kid"]
        new_kid = _new_kid()

        priv_bytes, pub_bytes = _generate_key_pair(key_size)
        encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
        await self._write_kid_pems(new_kid, encrypted_priv, pub_bytes)

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

        try:
            await self._save_keyring(self._keyring)
        except ConcurrentWriteError:
            # Another instance rotated first — reload and let
            # the caller retry. The new PEM we just wrote is
            # orphaned but harmless (no kid in the keyring
            # points to it).
            await self._reload_keyring()
            raise

        await self._write_active_copies(self._keyring)
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
        *kid* is not in the ring. Like :meth:`rotate`, the
        write goes through ``_write_json_versioned`` for
        cloud atomicity.
        """
        await self._ensure_loaded()
        if self._keyring is None:
            return
        if kid not in self._keyring["keys"]:
            return
        self._keyring["keys"][kid]["status"] = "revoked"
        self._keyring["keys"][kid]["revoked_at"] = datetime.now(timezone.utc).isoformat()
        try:
            await self._save_keyring(self._keyring)
        except ConcurrentWriteError:
            await self._reload_keyring()
            raise
        # No legacy copy update: revoking a non-active key does
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

    async def reload(self) -> None:
        """Force a re-read of the keyring from disk (useful
        after an external mutation, e.g. from the
        ``get_or_generate_keyring`` startup path).
        """
        await self._reload_keyring()

    @classmethod
    def for_keys_dir(
        cls, keys_dir: str, secret_key: str, key_size: int = 2048
    ) -> "FileKeyStoreRepository":
        """Build a temporary ``Settings`` instance for
        direct ``keys_dir`` access.

        Used by ``core.config.bootstrap_if_missing`` and
        ``auto_rotate_if_needed`` (the startup migration /
        auto-rotation paths) so the repository can read /
        write the keyring files without going through the
        ``lru_cache``'d global ``get_settings()``.

        The ``secret_key`` is unused here — it's accepted for
        symmetry with the upstream caller (which will
        encrypt the freshly-generated private key with it).
        """

        # Bypass ``Settings()`` instantiation (which would
        # recursively trigger ``get_or_generate_keyring``)
        # and construct a stub with just the attributes
        # :class:`BaseFileRepository` reads.
        class _KeysDirSettings:
            storage_backend = "file"

            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

            def get_storage_options(self) -> dict:
                return {}

        repo = cls(settings=_KeysDirSettings(keys_dir))  # type: ignore[arg-type]
        return repo

    async def get_keyring_dict(self) -> Optional[Dict[str, Any]]:
        """Return the in-memory keyring dict (for admin
        introspection). The pre-refactor ``JWTService.
        get_keyring_info`` returned a similar shape."""
        await self._ensure_loaded()
        if self._keyring is None:
            return None
        return self._keyring

    async def get_active_kid(self) -> Optional[str]:
        """Return the active ``kid``, or ``None`` if the
        keyring is missing."""
        await self._ensure_loaded()
        return self._active_kid

    # ------------------------------------------------------------------
    # Startup bootstrap (used by core.config.get_or_generate_keyring)
    # ------------------------------------------------------------------

    async def bootstrap_if_missing(
        self,
        secret_key: str,
        key_size: int = 2048,
    ) -> None:
        """Ensure the keyring exists. Called once at startup.

        1. If the keyring is missing AND the legacy
           ``private_key.pem`` / ``public_key.pem`` exist, migrate.
        2. If the keyring is missing AND no legacy files,
           generate a fresh keyring.
        3. Otherwise no-op.
        """
        await self._ensure_loaded()
        if self._keyring is not None:
            return

        if await self._exists(self._legacy_priv_path()) and await self._exists(
            self._legacy_pub_path()
        ):
            await self._migrate_legacy(secret_key, key_size)
            return

        await self._generate_fresh(secret_key, key_size)

    async def _migrate_legacy(self, secret_key: str, key_size: int) -> None:
        """Migrate the pre-keyring single-key layout to the
        per-kid directory layout. Reads the legacy
        ``private_key.pem`` / ``public_key.pem`` (assumed
        already-encrypted private bytes) and writes them to
        ``<kid>/{private,public}_key.pem``.
        """
        import structlog

        keys_log = structlog.get_logger("authglow.keys")
        keys_log.info("keyring_migration_started")

        kid = _LEGACY_KID
        priv_bytes = await self._afs.read_bytes(self._legacy_priv_path())
        pub_bytes = await self._afs.read_bytes(self._legacy_pub_path())
        await self._write_kid_pems(kid, priv_bytes, pub_bytes)

        keyring = {
            "active_kid": kid,
            "keys": {
                kid: {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": key_size,
                }
            },
        }
        await self._save_keyring(keyring)
        await self._write_active_copies(keyring)
        self._keyring = keyring
        self._active_kid = kid

    async def _generate_fresh(self, secret_key: str, key_size: int) -> None:
        """Generate a brand-new keyring with a single active key."""
        import structlog

        from authglow.core.crypto import encrypt_private_key

        keys_log = structlog.get_logger("authglow.keys")
        keys_log.info("keyring_generation_started")

        kid = _new_kid()
        priv_bytes, pub_bytes = _generate_key_pair(key_size)
        encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
        await self._write_kid_pems(kid, encrypted_priv, pub_bytes)

        keyring = {
            "active_kid": kid,
            "keys": {
                kid: {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": key_size,
                }
            },
        }
        await self._save_keyring(keyring)
        await self._write_active_copies(keyring)
        self._keyring = keyring
        self._active_kid = kid
        keys_log.info("keyring_initialised", kid=kid)

    async def auto_rotate_if_needed(
        self,
        secret_key: str,
        rotation_days: int,
        key_size: int = 2048,
    ) -> None:
        """Rotate the active key if it's older than *rotation_days*."""
        import structlog

        await self._ensure_loaded()
        if self._keyring is None or self._active_kid is None:
            return
        active_meta = self._keyring["keys"].get(self._active_kid, {})
        created_str = active_meta.get("created_at", "")
        if not created_str:
            return
        try:
            created_dt = datetime.fromisoformat(created_str)
        except ValueError:
            return
        age = datetime.now(timezone.utc) - created_dt
        if age.days < rotation_days:
            return

        keys_log = structlog.get_logger("authglow.keys")
        keys_log.info(
            "keyring_rotation_started",
            kid=self._active_kid,
            age_days=age.days,
            rotation_days=rotation_days,
        )
        try:
            await self.rotate(secret_key, key_size=key_size)
        except ConcurrentWriteError:
            # Another instance rotated first; reload and accept
            # their rotation as authoritative.
            await self._reload_keyring()
        else:
            keys_log.info(
                "keyring_rotated",
                old_kid=self._active_kid,
                new_kid=self._keyring["active_kid"],
            )
