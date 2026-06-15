"""Unit tests for the FileCSRFTokenRepository.

Covers the file layout, JSON round-trip, overwrite semantics,
expired-entry cleanup, and Protocol conformance. The service-level
behaviour (throttling, hash comparison) is exercised by
``tests/unit/test_csrf.py``.
"""

import time
from pathlib import Path
from unittest.mock import patch

from authglow.repositories.file.csrf import FileCSRFTokenRepository
from authglow.repositories.protocols import CSRFTokenRepository


def _make_repo(test_settings) -> FileCSRFTokenRepository:
    return FileCSRFTokenRepository(settings=test_settings)


class TestFileCSRFTokenRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "csrf_tokens"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileCSRFTokenRepository._subdir == "csrf_tokens"

    def test_default_storage_backend_file(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._filesystem is not None

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileCSRFTokenRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, CSRFTokenRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("save", "get", "delete", "cleanup_expired"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileCSRFTokenRepositorySaveGet:
    async def test_save_creates_file(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save("lookup-1", "hash-1", time.time() + 60, time.time())
        path = Path(repo._path("lookup-1.json"))
        assert path.exists()

    async def test_get_returns_dict(self, test_settings):
        repo = _make_repo(test_settings)
        now = time.time()
        await repo.save("lookup-2", "hash-2", now + 60, now)
        result = await repo.get("lookup-2")
        assert result is not None
        assert result["token_hash"] == "hash-2"
        assert result["expires_at"] == now + 60
        assert result["created_at"] == now

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get("nonexistent")
        assert result is None

    async def test_save_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save("lookup-3", "old-hash", time.time() + 60, time.time())
        await repo.save("lookup-3", "new-hash", time.time() + 120, time.time())
        result = await repo.get("lookup-3")
        assert result["token_hash"] == "new-hash"

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not valid json")
        result = await repo.get("corrupt")
        assert result is None


class TestFileCSRFTokenRepositoryDelete:
    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save("lookup-del", "hash", time.time() + 60, time.time())
        path = Path(repo._path("lookup-del.json"))
        assert path.exists()
        await repo.delete("lookup-del")
        assert not path.exists()

    async def test_delete_nonexistent_is_noop(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.delete("nope")
        assert True


class TestFileCSRFTokenRepositoryCleanup:
    async def test_cleanup_deletes_expired(self, test_settings):
        repo = _make_repo(test_settings)
        now = time.time()
        await repo.save("expired", "h1", now - 60, now - 120)
        await repo.save("alive", "h2", now + 60, now)
        await repo.cleanup_expired()
        assert await repo.get("expired") is None
        assert await repo.get("alive") is not None

    async def test_cleanup_empty_dir(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.cleanup_expired()
        assert True

    async def test_cleanup_handles_corrupt_file(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt2.json"))
        path.write_text("garbage")
        await repo.cleanup_expired()
        assert True


class TestFileCSRFTokenRepositoryWithPatchedSettings:
    def test_repo_can_be_constructed_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding.

        This mirrors how the dependency-injection factory
        (``get_csrf_token_repository``) constructs a repo per
        request.
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
            repo = FileCSRFTokenRepository()
            assert Path(repo._storage_path).exists()
