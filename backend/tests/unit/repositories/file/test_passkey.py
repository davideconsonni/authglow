"""Unit tests for the File-backed WebAuthn / passkey repositories.

Covers ``FilePasskeyRepository`` and ``FileWebAuthnChallengeRepository``.
The service-level behaviour (WebAuthn crypto, ``named_lock``, CAS
retry on ``update``) is exercised by
``tests/unit/test_passkey.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from authglow.core.datetime import utcnow
from authglow.models.passkey import Passkey, PasskeyChallenge
from authglow.repositories.file.passkey import (
    FilePasskeyRepository,
    FileWebAuthnChallengeRepository,
)
from authglow.repositories.protocols import (
    PasskeyRepository,
    WebAuthnChallengeRepository,
)


def _make_passkey(
    user_id: str = "user-1",
    credential_id: str = "cred-1",
    name: str = "Test Key",
) -> Passkey:
    return Passkey(
        credential_id=credential_id,
        public_key="pub-key-b64",
        sign_count=0,
        transports=["internal"],
        aaguid="00000000-0000-0000-0000-000000000000",
        user_id=user_id,
        name=name,
        device_type="phone",
    )


def _make_challenge(
    challenge: str = "challenge-1",
    user_id: str = "user-1",
    *,
    expires_in_seconds: int = 60,
    type: str = "registration",
) -> PasskeyChallenge:
    return PasskeyChallenge(
        challenge=challenge,
        user_id=user_id,
        expires_at=utcnow() + timedelta(seconds=expires_in_seconds),
        type=type,
    )


# ---------------------------------------------------------------------------
# FilePasskeyRepository
# ---------------------------------------------------------------------------


class TestFilePasskeyRepository:
    def _make_repo(self, test_settings) -> FilePasskeyRepository:
        return FilePasskeyRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "passkeys"
        assert Path(repo._storage_path).name == "passkeys"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, PasskeyRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("save", "get", "update", "delete", "list_for_user"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    async def test_save_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        pk = _make_passkey(user_id="u-rt", credential_id="c-rt")
        await repo.save(pk)
        loaded = await repo.get("u-rt", "c-rt")
        assert loaded is not None
        assert loaded.credential_id == "c-rt"
        assert loaded.user_id == "u-rt"
        assert loaded.name == "Test Key"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nobody", "nope") is None

    async def test_update_persists_last_used_and_sign_count(self, test_settings):
        repo = self._make_repo(test_settings)
        pk = _make_passkey(user_id="u-upd", credential_id="c-upd")
        await repo.save(pk)
        pk.last_used_at = utcnow()
        pk.sign_count = 42
        await repo.update(pk)
        loaded = await repo.get("u-upd", "c-upd")
        assert loaded is not None
        assert loaded.sign_count == 42
        assert loaded.last_used_at is not None

    async def test_update_missing_raises(self, test_settings):
        repo = self._make_repo(test_settings)
        pk = _make_passkey(user_id="u-miss", credential_id="c-miss")
        with pytest.raises(FileNotFoundError):
            await repo.update(pk)

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_passkey(user_id="u-del", credential_id="c-del"))
        result = await repo.delete("u-del", "c-del")
        assert result is True
        assert await repo.get("u-del", "c-del") is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nobody", "nope") is False

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_passkey(user_id="u-a", credential_id="c-1"))
        await repo.save(_make_passkey(user_id="u-a", credential_id="c-2"))
        await repo.save(_make_passkey(user_id="u-b", credential_id="c-1"))
        result = await repo.list_for_user("u-a")
        assert len(result) == 2
        assert all(pk.user_id == "u-a" for pk in result)

    async def test_list_for_user_returns_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list_for_user("nobody") == []

    async def test_list_for_user_sorted_desc(self, test_settings):
        import asyncio

        repo = self._make_repo(test_settings)
        pk_old = _make_passkey(user_id="u-sort", credential_id="c-old")
        await repo.save(pk_old)
        await asyncio.sleep(0.01)
        pk_new = _make_passkey(user_id="u-sort", credential_id="c-new")
        await repo.save(pk_new)
        result = await repo.list_for_user("u-sort")
        assert len(result) == 2
        assert result[0].credential_id == "c-new"
        assert result[1].credential_id == "c-old"

    async def test_corrupt_json_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        path = Path(repo._path_for("u-corrupt", "c-corrupt"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        assert await repo.get("u-corrupt", "c-corrupt") is None


# ---------------------------------------------------------------------------
# FileWebAuthnChallengeRepository
# ---------------------------------------------------------------------------


class TestFileWebAuthnChallengeRepository:
    def _make_repo(self, test_settings) -> FileWebAuthnChallengeRepository:
        return FileWebAuthnChallengeRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "challenges"
        assert Path(repo._storage_path).name == "challenges"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, WebAuthnChallengeRepository)

    async def test_save_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        ch = _make_challenge(challenge="c1", user_id="u1")
        await repo.save(ch)
        loaded = await repo.get("c1")
        assert loaded is not None
        assert loaded.challenge == "c1"
        assert loaded.user_id == "u1"
        assert loaded.type == "registration"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nope") is None

    async def test_get_auto_deletes_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        ch = _make_challenge(challenge="c-exp", user_id="u1", expires_in_seconds=-1)
        await repo.save(ch)
        path = Path(repo._path_for("c-exp"))
        assert path.exists()
        result = await repo.get("c-exp")
        assert result is None
        assert not path.exists()

    async def test_get_returns_expired_for_positive_seconds(self, test_settings):
        repo = self._make_repo(test_settings)
        ch = _make_challenge(challenge="c-ok", user_id="u1", expires_in_seconds=60)
        await repo.save(ch)
        loaded = await repo.get("c-ok")
        assert loaded is not None
        assert loaded.challenge == "c-ok"

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        ch = _make_challenge(challenge="c-del", user_id="u1")
        await repo.save(ch)
        await repo.delete("c-del")
        assert await repo.get("c-del") is None

    async def test_delete_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.delete("nope")


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFilePasskeyRepositoriesWithPatchedSettings:
    def test_both_construct_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructors resolve
        ``get_settings()`` via ``BaseFileRepository``'s binding.

        This is the FIX for the pre-refactor ``fsspec.core.url_to_fs``
        bypass: with the refactored repositories, a deployment that
        switches ``Settings.storage_backend`` to ``s3`` / ``gcs`` /
        ``abfs`` no longer crashes with a confusing ``ValueError``
        from fsspec.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            pk_repo = FilePasskeyRepository()
            ch_repo = FileWebAuthnChallengeRepository()
            assert Path(pk_repo._storage_path).exists()
            assert Path(ch_repo._storage_path).exists()
