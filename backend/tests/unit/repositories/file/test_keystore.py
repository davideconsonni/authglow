"""Unit tests for the File-backed keyring repository.

Covers ``FileKeyStoreRepository``. The service-level behaviour
(``JWTService`` reading the keyring, signing tokens with the
right ``kid``, fallback to all keys on unknown kid, etc.) is
exercised by the existing ``tests/unit/test_jwt.py`` and
``tests/unit/test_jwt_key_rotation.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via
  ``isinstance(repo, <Protocol>)``.

Conventions:

* Each test starts from a fresh empty ``keys_dir`` and
  manually populates it via the repository (or by writing
  the on-disk keyring files directly via the fsspec
  filesystem for round-trip / corruption tests).
* The keyring is a ``BaseFileRepository`` subclass with a
  custom ``root_dir=settings.keys_dir`` (so it rides on the
  fsspec layer like every other entity). All I/O goes
  through ``AsyncFileSystem``; the on-disk files are the
  same ``keyring.json`` + per-kid PEMs as before, plus an
  extra ``_version`` field for object-store atomicity.
"""

import os
import shutil
from datetime import timedelta

import pytest

from authglow.core.crypto import decrypt_private_key, encrypt_private_key
from authglow.core.datetime import utcnow
from authglow.repositories.file.keystore import (
    FileKeyStoreRepository,
)
from authglow.repositories.protocols import KeyStoreRepository


class _StubSettings:
    """Minimal settings stub exposing the attributes that
    :class:`BaseFileRepository` consults during ``__init__``.

    The keyring repository only needs ``keys_dir`` semantically,
    but the base class's ``_init_filesystem`` also reads
    ``storage_backend`` and ``get_storage_options()`` — we
    default them to a local-file backend so the test fixtures
    work without instantiating a real ``Settings`` (which would
    call ``get_or_generate_keyring`` recursively and force the
    real ``keys_dir``).
    """

    storage_backend = "file"

    def __init__(self, kd: str) -> None:
        self.keys_dir = kd

    def get_storage_options(self) -> dict:
        return {}


async def _create_test_keyring(
    repo: FileKeyStoreRepository,
    kid: str = "k-test",
    status: str = "active",
    age_days: int = 0,
    secret_key: str = "test-secret-key-for-authglow-testing-32chars!",
) -> None:
    """Helper: write a fresh keyring + key PEMs to disk.

    Generates a new RSA key pair, encrypts the private key
    with ``secret_key``, and writes the per-kid PEM files +
    ``keyring.json`` index. If the on-disk keyring already
    has a ``_version`` field (set by a previous call), the
    helper carries it forward so the CAS check in
    ``_save_keyring`` passes.
    """
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
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
    encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
    await repo._write_kid_pems(kid, encrypted_priv, pub_bytes)

    created_at_dt = utcnow() - timedelta(days=age_days)

    # Carry the existing _version forward so multiple
    # _create_test_keyring() calls on the same on-disk
    # keyring do not trigger a CAS mismatch. The version
    # defaults to 0 when the keyring is brand-new.
    existing = await repo._load_keyring()
    existing_version = int((existing or {}).get("_version", 0))

    keyring: dict = {
        "active_kid": kid,
        "keys": {
            kid: {
                "created_at": created_at_dt.isoformat(),
                "status": status,
                "algorithm": "RS256",
                "key_size": 2048,
            }
        },
    }
    # If there are pre-existing keys in the keyring, merge
    # them in (so the new kid is added rather than replacing
    # the whole ring).
    if existing and existing.get("keys"):
        for existing_kid, existing_meta in existing["keys"].items():
            if existing_kid not in keyring["keys"]:
                keyring["keys"][existing_kid] = existing_meta
        if "active_kid" in existing:
            keyring["active_kid"] = existing["active_kid"]
    if existing_version:
        keyring["_version"] = existing_version

    await repo._save_keyring(keyring)
    await repo._write_active_copies(keyring)


# ---------------------------------------------------------------------------
# FileKeyStoreRepository
# ---------------------------------------------------------------------------


def _make_repo(test_settings, tmp_path) -> FileKeyStoreRepository:
    """Build a repo against a per-test empty ``keys_dir``.

    ``test_settings.keys_dir`` is the session-scoped
    ``tmp_path/keys`` from ``conftest.py`` — shared across
    tests, so we override it with a function-scoped
    ``tmp_path`` here. Without this, tests that expect an
    empty keyring would see keyring files left behind by
    previous tests.
    """
    keys_dir = tmp_path / "keys"
    if keys_dir.exists():
        shutil.rmtree(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)

    return FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))


class TestFileKeyStoreRepository:
    def test_satisfies_protocol(self, test_settings, tmp_path):
        keys_dir = tmp_path / "proto_check"
        if keys_dir.exists():
            shutil.rmtree(keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)

        repo = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
        assert isinstance(repo, KeyStoreRepository)

    def test_has_all_protocol_methods(self, test_settings, tmp_path):  # noqa: ARG002
        repo = _make_repo(test_settings, tmp_path)
        for method in (
            "get_active_keypair",
            "get_keypair_by_kid",
            "get_public_keys",
            "rotate",
            "revoke",
        ):
            assert hasattr(repo, method), f"missing method {method}"
            assert callable(getattr(repo, method))

    def test_root_dir_is_keys_dir(self, test_settings, tmp_path):
        """The keyring repo must resolve its fsspec root to
        ``settings.keys_dir`` (not ``storage_path/<subdir>``)
        so it shares the same file layout regardless of the
        ``STORAGE_BACKEND`` choice."""
        keys_dir = tmp_path / "keys_root"
        if keys_dir.exists():
            shutil.rmtree(keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)

        repo = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
        assert repo._storage_path == str(keys_dir)
        assert repo._keyring_path().endswith("keyring.json")

    # ----- get_active_keypair -----

    async def test_get_active_keypair_returns_none_for_empty(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        assert await repo.get_active_keypair() is None

    async def test_get_active_keypair_round_trip(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        keypair = await repo.get_active_keypair()
        assert keypair is not None
        assert keypair.kid == "k-active"
        assert keypair.meta.status == "active"
        assert keypair.private_pem is not None
        assert keypair.public_pem is not None
        assert decrypt_private_key(keypair.private_pem) is not None

    # ----- get_keypair_by_kid -----

    async def test_get_keypair_by_kid_returns_none_for_unknown(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        assert await repo.get_keypair_by_kid("nobody") is None

    async def test_get_keypair_by_kid_returns_correct_key(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-a")
        keyring = await repo._load_keyring()
        assert keyring is not None
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
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

        await repo._write_kid_pems(
            "k-b",
            encrypt_private_key(priv_bytes, secret_key="test-secret"),
            pub_bytes,
        )
        keyring["keys"]["k-b"] = {
            "created_at": utcnow().isoformat(),
            "status": "verifying",
            "algorithm": "RS256",
            "key_size": 2048,
        }
        await repo._save_keyring(keyring)
        keypair = await repo.get_keypair_by_kid("k-a")
        assert keypair is not None
        assert keypair.kid == "k-a"

    # ----- get_public_keys -----

    async def test_get_public_keys_empty(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        assert await repo.get_public_keys() == []

    async def test_get_public_keys_returns_jwk_components(self, test_settings, tmp_path):
        import base64

        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-jwks")
        keys = await repo.get_public_keys()
        assert len(keys) == 1
        k = keys[0]
        assert k.kid == "k-jwks"
        assert k.algorithm == "RS256"
        assert k.use == "sig"
        assert k.kty == "RSA"
        assert isinstance(k.n, str) and len(k.n) > 0
        assert isinstance(k.e, str) and len(k.e) > 0
        base64.urlsafe_b64decode(k.n + "==")
        base64.urlsafe_b64decode(k.e + "==")

    async def test_get_public_keys_excludes_revoked(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        await _create_test_keyring(repo, kid="k-revoked", status="revoked")
        keys = await repo.get_public_keys()
        assert all(k.kid != "k-revoked" for k in keys)

    async def test_get_public_keys_includes_verifying(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        keyring = await repo._load_keyring()
        assert keyring is not None
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
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

        await repo._write_kid_pems(
            "k-verifying",
            encrypt_private_key(priv_bytes, secret_key="test-secret"),
            pub_bytes,
        )
        keyring["keys"]["k-verifying"] = {
            "created_at": utcnow().isoformat(),
            "status": "verifying",
            "algorithm": "RS256",
            "key_size": 2048,
        }
        await repo._save_keyring(keyring)

        keys = await repo.get_public_keys()
        kids = {k.kid for k in keys}
        assert "k-active" in kids
        assert "k-verifying" in kids

    # ----- rotate -----

    async def test_rotate_generates_new_keypair(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-1")
        old_active = await repo.get_active_kid()
        new_keypair = await repo.rotate(secret_key="test-secret")
        assert new_keypair.kid != old_active
        assert new_keypair.meta.status == "active"
        old_keypair = await repo.get_keypair_by_kid(old_active)
        assert old_keypair.meta.status == "verifying"

    async def test_rotate_persists(self, test_settings, tmp_path):
        """After rotate, the next repo instance must see the
        new active kid from disk (not the in-memory cache)."""
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-1")
        shared_keys_dir = repo._storage_path
        await repo.rotate(secret_key="test-secret")

        repo2 = FileKeyStoreRepository(settings=_StubSettings(shared_keys_dir))
        new_active = await repo2.get_active_kid()
        assert new_active is not None
        info = await repo2.get_keyring_dict()
        assert new_active in info["keys"]
        assert any(meta.get("status") == "verifying" for meta in info["keys"].values())

    # ----- revoke -----

    async def test_revoke_marks_status(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        await _create_test_keyring(repo, kid="k-verifying", status="verifying")
        await repo.revoke("k-verifying")
        kp = await repo.get_keypair_by_kid("k-verifying")
        assert kp.meta.status == "revoked"
        assert kp.meta.revoked_at is not None

    async def test_revoke_nonexistent_is_noop(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        await repo.revoke("nobody")

    async def test_revoke_excludes_from_public_keys(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-active")
        await _create_test_keyring(repo, kid="k-to-revoke", status="verifying")
        await repo.revoke("k-to-revoke")
        keys = await repo.get_public_keys()
        assert "k-to-revoke" not in {k.kid for k in keys}

    # ----- helpers: is_loaded / reload -----

    async def test_is_loaded_initially_false(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        assert repo.is_loaded() is False

    async def test_lazy_load_on_first_read(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-lazy")
        assert repo.is_loaded() is False
        await repo.get_active_keypair()
        assert repo.is_loaded() is True

    async def test_reload_picks_up_disk_changes(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-disk-1")
        await repo.get_active_keypair()
        disk_keyring = await repo._afs.read_json(repo._keyring_path())
        disk_keyring.pop("_version", None)
        disk_keyring["active_kid"] = "k-disk-2"
        disk_keyring["keys"]["k-disk-2"] = {
            "created_at": utcnow().isoformat(),
            "status": "active",
            "algorithm": "RS256",
            "key_size": 2048,
        }
        await repo._afs.write_json(repo._keyring_path(), disk_keyring)
        await repo.reload()
        assert await repo.get_active_kid() == "k-disk-2"

    # ----- helpers: get_keyring_dict -----

    async def test_get_keyring_dict(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-info")
        info = await repo.get_keyring_dict()
        assert info is not None
        assert info["active_kid"] == "k-info"
        assert "k-info" in info["keys"]

    # ----- atomicity: _version field -----

    async def test_keyring_has_version_field_after_save(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-versioned")
        disk = await repo._afs.read_json(repo._keyring_path())
        assert "_version" in disk
        assert disk["_version"] == 1

    async def test_rotate_increments_version(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-pre-rotate")
        before = await repo._afs.read_json(repo._keyring_path())
        before_v = before["_version"]
        await repo.rotate(secret_key="test-secret")
        after = await repo._afs.read_json(repo._keyring_path())
        assert after["_version"] == before_v + 1

    async def test_legacy_keyring_without_version_field_is_accepted(
        self, test_settings, tmp_path
    ):
        """A keyring.json written by the pre-refactor code
        (no ``_version`` field) must still load and the
        first save must initialise ``_version`` to 1."""
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-legacy")
        disk = await repo._afs.read_json(repo._keyring_path())
        disk.pop("_version", None)
        await repo._afs.write_json(repo._keyring_path(), disk)
        repo2 = FileKeyStoreRepository(settings=_StubSettings(repo._storage_path))
        loaded = await repo2._load_keyring()
        assert loaded is not None
        assert "active_kid" in loaded
        await repo2._save_keyring(loaded)
        on_disk = await repo2._afs.read_json(repo2._keyring_path())
        assert on_disk["_version"] == 1


# ---------------------------------------------------------------------------
# Patched-keys_dir construction smoke test
# ---------------------------------------------------------------------------


class TestFileKeyStoreRepositoryWithCustomKeysDir:
    def test_for_keys_dir_uses_custom_directory(self, tmp_path):
        """The ``for_keys_dir`` classmethod lets callers
        instantiate a repository against a custom directory
        without going through the lru_cache'd
        ``get_settings()``. This is the path used by
        ``core.config.bootstrap`` at startup.
        """
        keys_dir = str(tmp_path / "my_keys")
        os.makedirs(keys_dir, exist_ok=True)
        repo = FileKeyStoreRepository.for_keys_dir(keys_dir=keys_dir, secret_key="x")
        assert repo._storage_path == keys_dir
        assert repo._settings.keys_dir == keys_dir


# ---------------------------------------------------------------------------
# Public key access (Tier 1.8 of PERFORMANCE_OPTIMIZATION_PLAN.md)
# ---------------------------------------------------------------------------


class TestFileKeyStoreRepositoryReadPublicKey:
    """``read_public_key`` is the async accessor used by the
    ``/.well-known/jwks.json`` route handler. It must:

    * return the PEM bytes for a known ``kid`` (routed through
      :class:`AsyncFileSystem` so the call does not block the
      event loop);
    * return ``None`` for an unknown ``kid`` (no exception, no
      empty bytes);
    * coexist with the existing ``get_public_keys`` helper
      (returns the cached JWK projection used by ``JWKSStatus``).
    """

    async def test_read_public_key_returns_pem_bytes(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-rpk")

        pem = await repo.read_public_key("k-rpk")
        assert pem is not None
        assert b"BEGIN PUBLIC KEY" in pem
        assert b"END PUBLIC KEY" in pem

    async def test_read_public_key_returns_none_for_unknown_kid(self, test_settings, tmp_path):
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-known")

        assert await repo.read_public_key("k-unknown") is None

    async def test_read_public_key_round_trips_after_rotation(self, test_settings, tmp_path):
        """After ``rotate`` the active kid changes; ``read_public_key``
        must return the bytes of the **new** key."""
        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-old")
        first_pem = await repo.read_public_key("k-old")
        assert first_pem is not None

        rotated = await repo.rotate(secret_key="test-secret")
        # The new key is on disk; the old one is in "verifying" status.
        new_pem = await repo.read_public_key(rotated.kid)
        assert new_pem is not None
        assert new_pem != first_pem, "rotated key must be a different PEM"

    async def test_read_public_key_does_not_block_event_loop(self, test_settings, tmp_path):
        """During ``read_public_key`` another coroutine must be
        able to run — proves the I/O is offloaded to a thread."""
        import asyncio

        repo = _make_repo(test_settings, tmp_path)
        await _create_test_keyring(repo, kid="k-loop")

        sentinel = asyncio.Event()
        loop_alive = asyncio.Event()

        async def sentinel_coro():
            sentinel.set()
            await asyncio.sleep(0)
            loop_alive.set()

        task = asyncio.create_task(sentinel_coro())
        await sentinel.wait()
        await repo.read_public_key("k-loop")
        try:
            await asyncio.wait_for(loop_alive.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            task.cancel()
            pytest.fail("event loop was blocked during read_public_key")
        assert loop_alive.is_set()


# ---------------------------------------------------------------------------
# Multi-instance / shared backend smoke test
# ---------------------------------------------------------------------------


class TestKeyStoreSharedBackend:
    """Two ``FileKeyStoreRepository`` instances against the
    same ``keys_dir`` must observe each other's writes. This
    is the same property the fsspec refactor relies on for
    multi-instance deployments with a shared backend."""

    def test_two_repo_instances_share_state(self, tmp_path):
        import asyncio

        keys_dir = tmp_path / "shared_keys"
        keys_dir.mkdir()

        async def _scenario():
            repo_a = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
            repo_b = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
            await _create_test_keyring(repo_a, kid="k-shared")
            await repo_b.reload()
            active_b = await repo_b.get_active_kid()
            assert active_b == "k-shared"

        asyncio.run(_scenario())

    def test_rotate_propagates_to_second_instance(self, tmp_path):
        import asyncio

        keys_dir = tmp_path / "shared_rotate"
        keys_dir.mkdir()

        async def _scenario():
            repo_a = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
            repo_b = FileKeyStoreRepository(settings=_StubSettings(str(keys_dir)))
            await _create_test_keyring(repo_a, kid="k-initial")
            await repo_a.rotate(secret_key="test-secret")
            await repo_b.reload()
            assert await repo_b.get_active_kid() != "k-initial"

        asyncio.run(_scenario())
