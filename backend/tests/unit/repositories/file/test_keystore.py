"""Unit tests for the File-backed keyring repository.

Covers ``FileKeyStoreRepository``. The service-level behaviour
(``JWTService`` reading the keyring, signing tokens with the
right ``kid``, fallback to all keys on unknown kid, etc.) is
exercised by the existing ``tests/unit/test_jwt.py`` and
``tests/unit/test_jwt_key_rotation.py`` (49 tests combined).

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via
  ``isinstance(repo, <Protocol>)``.

Conventions:

* Each test starts from a fresh empty ``keys_dir`` and
  manually populates it via the repository (or by writing
  the on-disk keyring files directly for round-trip /
  corruption tests).
* The keyring is **not** a ``BaseFileRepository`` subclass
  (the keyring layout spans multiple files: the index +
  per-kid PEM files + the legacy flat paths). The
  ``tmp+rename`` atomic-write pattern is implemented
  inline (matches the pre-refactor behaviour).
"""

import base64
import json
import os
import shutil
from datetime import timedelta

from authglow.core.crypto import decrypt_private_key, encrypt_private_key
from authglow.core.datetime import utcnow
from authglow.repositories.file.keystore import (
    FileKeyStoreRepository,
)
from authglow.repositories.protocols import KeyStoreRepository


def _create_test_keyring(
    repo: FileKeyStoreRepository,
    kid: str = "k-test",
    status: str = "active",
    age_days: int = 0,
    secret_key: str = "test-secret-key-for-authglow-testing-32chars!",
) -> None:
    """Helper: write a fresh keyring + key PEMs to disk.

    Generates a new RSA key pair, encrypts the private key
    with ``secret_key``, and writes the per-kid PEM files +
    ``keyring.json`` index.
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
    repo._write_kid_pems(kid, encrypted_priv, pub_bytes)

    created_at_dt = utcnow() - timedelta(days=age_days)
    keyring = {
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
    repo._save_keyring(keyring)
    repo._write_active_symlinks(keyring)


# ---------------------------------------------------------------------------
# FileKeyStoreRepository
# ---------------------------------------------------------------------------


class TestFileKeyStoreRepository:
    def _make_repo(self, test_settings, tmp_path) -> FileKeyStoreRepository:
        """Build a repo against a per-test empty ``keys_dir``.

        ``test_settings.keys_dir`` is the session-scoped
        ``tmp_path/keys`` from ``conftest.py`` — shared across
        tests, so we override it with a function-scoped
        ``tmp_path`` here. Without this, tests that expect an
        empty keyring would see keyring files left behind by
        previous tests (which is the
        ``lru_cache``-style isolation issue we hit on every
        other repository in earlier phases).
        """

        keys_dir = tmp_path / "keys"
        if keys_dir.exists():
            shutil.rmtree(keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)

        # Build a stub settings binding to the per-test
        # keys_dir. The repo only reads ``settings.keys_dir``,
        # so a minimal stub is enough.
        class _StubSettings:
            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

        return FileKeyStoreRepository(  # type: ignore[arg-type]
            settings=_StubSettings(str(keys_dir))
        )

    def test_satisfies_protocol(self, test_settings, tmp_path):
        # Inline construction (not via _make_repo) so pytest's
        # ``tmp_path`` fixture is in scope. The test only
        # checks Protocol conformance, so the keys_dir can be
        # any empty path under ``tmp_path``.

        keys_dir = tmp_path / "proto_check"
        if keys_dir.exists():
            shutil.rmtree(keys_dir)
        keys_dir.mkdir(parents=True, exist_ok=True)

        class _StubSettings:
            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

        repo = FileKeyStoreRepository(  # type: ignore[arg-type]
            settings=_StubSettings(str(keys_dir))
        )
        assert isinstance(repo, KeyStoreRepository)

    def test_has_all_protocol_methods(self, test_settings, tmp_path):  # noqa: ARG002
        repo = self._make_repo(test_settings, tmp_path)
        for method in (
            "get_active_keypair",
            "get_keypair_by_kid",
            "get_public_keys",
            "rotate",
            "revoke",
        ):
            assert hasattr(repo, method), f"missing method {method}"
            assert callable(getattr(repo, method))

    # ----- get_active_keypair -----

    async def test_get_active_keypair_returns_none_for_empty(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        assert await repo.get_active_keypair() is None

    async def test_get_active_keypair_round_trip(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        keypair = await repo.get_active_keypair()
        assert keypair is not None
        assert keypair.kid == "k-active"
        assert keypair.meta.status == "active"
        assert keypair.private_pem is not None
        assert keypair.public_pem is not None
        # Private key is encrypted (not raw PKCS8 plaintext)
        assert decrypt_private_key(keypair.private_pem) is not None

    # ----- get_keypair_by_kid -----

    async def test_get_keypair_by_kid_returns_none_for_unknown(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        assert await repo.get_keypair_by_kid("nobody") is None

    async def test_get_keypair_by_kid_returns_correct_key(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        # Manually populate a keyring with 2 keys: k-a (active)
        # and k-b (verifying) — the helper overwrites the
        # active_kid, so we have to build the keyring dict by
        # hand.
        _create_test_keyring(repo, kid="k-a")
        keyring = json.loads(open(repo._keyring_path, encoding="utf-8").read())
        # Build a second keypair for k-b
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
        from authglow.core.crypto import encrypt_private_key

        repo._write_kid_pems(
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
        # k-a stays active
        with open(repo._keyring_path, "w", encoding="utf-8") as f:
            json.dump(keyring, f)
        # k-b is verifying; k-a is still the active kid
        keypair = await repo.get_keypair_by_kid("k-a")
        assert keypair is not None
        assert keypair.kid == "k-a"

    # ----- get_public_keys -----

    async def test_get_public_keys_empty(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        assert await repo.get_public_keys() == []

    async def test_get_public_keys_returns_jwk_components(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-jwks")
        keys = await repo.get_public_keys()
        assert len(keys) == 1
        k = keys[0]
        assert k.kid == "k-jwks"
        assert k.algorithm == "RS256"
        assert k.use == "sig"
        assert k.kty == "RSA"
        # n / e are base64url-encoded (no padding)
        assert isinstance(k.n, str) and len(k.n) > 0
        assert isinstance(k.e, str) and len(k.e) > 0
        # base64url decode must succeed
        base64.urlsafe_b64decode(k.n + "==")
        base64.urlsafe_b64decode(k.e + "==")

    async def test_get_public_keys_excludes_revoked(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        _create_test_keyring(repo, kid="k-revoked", status="revoked")
        keys = await repo.get_public_keys()
        # Revoked key MUST be excluded
        assert all(k.kid != "k-revoked" for k in keys)

    async def test_get_public_keys_includes_verifying(self, test_settings, tmp_path):
        """Verifying (retired) keys are included so existing
        tokens (signed before the rotation) can still be
        verified."""
        repo = self._make_repo(test_settings, tmp_path)
        # Manually build a 2-key keyring (active + verifying)
        # because ``_create_test_keyring`` overwrites the
        # active_kid on each call.
        _create_test_keyring(repo, kid="k-active")
        keyring = json.loads(open(repo._keyring_path, encoding="utf-8").read())
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
        from authglow.core.crypto import encrypt_private_key

        repo._write_kid_pems(
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
        with open(repo._keyring_path, "w", encoding="utf-8") as f:
            json.dump(keyring, f)

        keys = await repo.get_public_keys()
        kids = {k.kid for k in keys}
        assert "k-active" in kids
        assert "k-verifying" in kids

    # ----- rotate -----

    async def test_rotate_generates_new_keypair(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-1")
        old_active = repo.get_active_kid()
        new_keypair = await repo.rotate(secret_key="test-secret")
        assert new_keypair.kid != old_active
        assert new_keypair.meta.status == "active"
        # Old key is now verifying
        old_keypair = await repo.get_keypair_by_kid(old_active)
        assert old_keypair.meta.status == "verifying"

    async def test_rotate_persists(self, test_settings, tmp_path):
        """After rotate, the next repo instance must see the
        new active kid from disk (not the in-memory cache)."""
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-1")
        # Capture the keys_dir used by the first repo so the
        # second instance reads from the SAME on-disk keyring
        # (otherwise it would create a fresh empty keys_dir).
        shared_keys_dir = repo._keys_dir
        await repo.rotate(secret_key="test-secret")

        # Re-instantiate against the SAME keys_dir
        class _StubSettings:
            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

        repo2 = FileKeyStoreRepository(  # type: ignore[arg-type]
            settings=_StubSettings(shared_keys_dir)
        )
        new_active = repo2.get_active_kid()
        # Disk state has 2 keys (old verifying + new active)
        assert new_active is not None
        info = repo2.get_keyring_dict()
        assert new_active in info["keys"]
        assert any(meta.get("status") == "verifying" for meta in info["keys"].values())

    # ----- revoke -----

    async def test_revoke_marks_status(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        _create_test_keyring(repo, kid="k-verifying", status="verifying")
        await repo.revoke("k-verifying")
        kp = await repo.get_keypair_by_kid("k-verifying")
        assert kp.meta.status == "revoked"
        assert kp.meta.revoked_at is not None

    async def test_revoke_nonexistent_is_noop(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        # No prior call to revoke — must not raise.
        await repo.revoke("nobody")

    async def test_revoke_excludes_from_public_keys(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-active")
        _create_test_keyring(repo, kid="k-to-revoke", status="verifying")
        await repo.revoke("k-to-revoke")
        keys = await repo.get_public_keys()
        assert "k-to-revoke" not in {k.kid for k in keys}

    # ----- helpers: is_loaded / reload -----

    async def test_is_loaded_initially_false(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        assert repo.is_loaded() is False

    async def test_lazy_load_on_first_read(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-lazy")
        assert repo.is_loaded() is False
        # First read triggers the load
        await repo.get_active_keypair()
        assert repo.is_loaded() is True

    async def test_reload_picks_up_disk_changes(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-disk-1")
        await repo.get_active_keypair()  # trigger initial load
        # Mutate the disk file directly
        disk_keyring = json.loads(open(repo._keyring_path, encoding="utf-8").read())
        disk_keyring["active_kid"] = "k-disk-2"
        disk_keyring["keys"]["k-disk-2"] = {
            "created_at": utcnow().isoformat(),
            "status": "active",
            "algorithm": "RS256",
            "key_size": 2048,
        }
        with open(repo._keyring_path, "w", encoding="utf-8") as f:
            json.dump(disk_keyring, f)
        # Reload picks up the change
        repo.reload()
        assert repo.get_active_kid() == "k-disk-2"

    # ----- helpers: get_keyring_dict -----

    async def test_get_keyring_dict(self, test_settings, tmp_path):
        repo = self._make_repo(test_settings, tmp_path)
        _create_test_keyring(repo, kid="k-info")
        info = repo.get_keyring_dict()
        assert info is not None
        assert info["active_kid"] == "k-info"
        assert "k-info" in info["keys"]


# ---------------------------------------------------------------------------
# Patched-keys_dir construction smoke test
# ---------------------------------------------------------------------------


class TestFileKeyStoreRepositoryWithCustomKeysDir:
    def test_for_keys_dir_uses_custom_directory(self, tmp_path):
        """The ``for_keys_dir`` classmethod lets callers
        instantiate a repository against a custom directory
        without going through the lru_cache'd
        ``get_settings()``. This is the path used by
        ``core.config._generate_fresh_keyring`` and
        ``_perform_rotation`` at startup.
        """
        keys_dir = str(tmp_path / "my_keys")
        os.makedirs(keys_dir, exist_ok=True)
        repo = FileKeyStoreRepository.for_keys_dir(keys_dir=keys_dir, secret_key="x")
        assert repo._keys_dir == keys_dir
        # The settings binding has the right keys_dir
        assert repo.settings.keys_dir == keys_dir
