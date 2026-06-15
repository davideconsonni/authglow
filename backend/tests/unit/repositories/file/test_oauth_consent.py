"""Unit tests for the FileOAuth2ConsentRepository.

Covers the deterministic ``{user_id}/{client_id}.json`` path
layout, the O(1) direct lookup, the admin scans (``get_by_id``,
``list_for_user``, ``list_all``), the revocation-update path, the
expired-consent auto-delete, and Protocol conformance. The
service-level behaviour (in-process lock, email filter,
``list_all_for_admin`` DTO conversion) is exercised by
``tests/unit/test_oauth_consent_service.py``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.oauth_consent import OAuth2Consent
from authglow.repositories.file.oauth_consent import (
    FileOAuth2ConsentRepository,
)
from authglow.repositories.protocols import OAuth2ConsentRepository


def _make_repo(test_settings) -> FileOAuth2ConsentRepository:
    return FileOAuth2ConsentRepository(settings=test_settings)


def _make_consent(
    user_id: str = "user-1",
    client_id: str = "client-1",
    *,
    revoked: bool = False,
    expires_at=None,
    scopes=None,
) -> OAuth2Consent:
    return OAuth2Consent(
        user_id=user_id,
        client_id=client_id,
        scopes=scopes or ["read"],
        expires_at=expires_at,
        revoked=revoked,
    )


class TestFileOAuth2ConsentRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "oauth_consents"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileOAuth2ConsentRepository._subdir == "oauth_consents"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileOAuth2ConsentRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, OAuth2ConsentRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in (
            "create",
            "get_by_id",
            "get_for_user_client",
            "update",
            "delete_for_user_client",
            "list_for_user",
            "list_all",
            "cleanup_expired",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileOAuth2ConsentRepositoryCreate:
    async def test_create_writes_nested_file(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-1", client_id="c-1")
        await repo.create(consent)
        path = Path(repo._path_for("u-1", "c-1"))
        assert path.exists()
        # Parent directory is also created
        assert path.parent.exists()

    async def test_create_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        c1 = _make_consent(user_id="u-ow", client_id="c-ow", scopes=["read"])
        c2 = _make_consent(user_id="u-ow", client_id="c-ow", scopes=["read", "write"])
        await repo.create(c1)
        await repo.create(c2)
        result = await repo.get_for_user_client("u-ow", "c-ow")
        assert result.scopes == ["read", "write"]


class TestFileOAuth2ConsentRepositoryGetById:
    async def test_get_by_id_returns_consent(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-1", client_id="c-1")
        await repo.create(consent)
        result = await repo.get_by_id(consent.consent_id)
        assert result is not None
        assert result.consent_id == consent.consent_id

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_id("nonexistent-id")
        assert result is None


class TestFileOAuth2ConsentRepositoryGetForUserClient:
    async def test_get_returns_consent(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-hit", client_id="c-hit")
        await repo.create(consent)
        result = await repo.get_for_user_client("u-hit", "c-hit")
        assert result is not None
        assert result.user_id == "u-hit"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_for_user_client("u-miss", "c-miss")
        assert result is None

    async def test_get_returns_none_for_revoked(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-rev", client_id="c-rev", revoked=True)
        await repo.create(consent)
        result = await repo.get_for_user_client("u-rev", "c-rev")
        assert result is None

    async def test_get_auto_deletes_expired(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(
            user_id="u-exp",
            client_id="c-exp",
            expires_at=utcnow() - timedelta(days=1),
        )
        await repo.create(consent)
        path = Path(repo._path_for("u-exp", "c-exp"))
        assert path.exists()
        result = await repo.get_for_user_client("u-exp", "c-exp")
        assert result is None
        assert not path.exists()


class TestFileOAuth2ConsentRepositoryUpdate:
    async def test_update_persists_revocation(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-upd", client_id="c-upd")
        await repo.create(consent)
        consent.revoked = True
        consent.revoked_at = utcnow()
        await repo.update(consent)
        # After update, the file still exists and revoked is True
        path = Path(repo._path_for("u-upd", "c-upd"))
        assert path.exists()
        # get_for_user_client returns None for revoked
        result = await repo.get_for_user_client("u-upd", "c-upd")
        assert result is None


class TestFileOAuth2ConsentRepositoryDelete:
    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        consent = _make_consent(user_id="u-del", client_id="c-del")
        await repo.create(consent)
        path = Path(repo._path_for("u-del", "c-del"))
        assert path.exists()
        result = await repo.delete_for_user_client("u-del", "c-del")
        assert result is True
        assert not path.exists()

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.delete_for_user_client("u-miss", "c-miss")
        assert result is False


class TestFileOAuth2ConsentRepositoryList:
    async def test_list_for_user_returns_only_user_consents(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_consent(user_id="u-a", client_id="c-1"))
        await repo.create(_make_consent(user_id="u-a", client_id="c-2"))
        await repo.create(_make_consent(user_id="u-b", client_id="c-1"))
        result = await repo.list_for_user("u-a")
        assert len(result) == 2
        assert all(c.user_id == "u-a" for c in result)

    async def test_list_for_user_returns_empty(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.list_for_user("nonexistent")
        assert result == []

    async def test_list_all_returns_all_consents(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_consent(user_id="u-1", client_id="c-1"))
        await repo.create(_make_consent(user_id="u-2", client_id="c-2"))
        await repo.create(_make_consent(user_id="u-3", client_id="c-3"))
        result = await repo.list_all()
        assert len(result) == 3

    async def test_list_all_pagination(self, test_settings):
        repo = _make_repo(test_settings)
        for i in range(5):
            await repo.create(_make_consent(user_id=f"u-{i:02d}", client_id=f"c-{i:02d}"))
        page1 = await repo.list_all(limit=2, offset=0)
        page2 = await repo.list_all(limit=2, offset=2)
        page3 = await repo.list_all(limit=2, offset=4)
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1


class TestFileOAuth2ConsentRepositoryCleanup:
    async def test_cleanup_deletes_expired(self, test_settings):
        repo = _make_repo(test_settings)
        expired = _make_consent(
            user_id="u-exp", client_id="c-exp", expires_at=utcnow() - timedelta(days=1)
        )
        valid = _make_consent(user_id="u-ok", client_id="c-ok")
        await repo.create(expired)
        await repo.create(valid)
        deleted = await repo.cleanup_expired()
        assert deleted == 1
        assert await repo.get_for_user_client("u-exp", "c-exp") is None
        assert await repo.get_for_user_client("u-ok", "c-ok") is not None

    async def test_cleanup_keeps_no_expiry(self, test_settings):
        repo = _make_repo(test_settings)
        no_expiry = _make_consent(user_id="u-noex", client_id="c-noex", expires_at=None)
        await repo.create(no_expiry)
        deleted = await repo.cleanup_expired()
        assert deleted == 0


class TestFileOAuth2ConsentRepositoryWithPatchedSettings:
    def test_repo_can_be_constructed_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding."""
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
            repo = FileOAuth2ConsentRepository()
            assert Path(repo._storage_path).exists()
