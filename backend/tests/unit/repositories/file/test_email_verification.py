"""Unit tests for the FileEmailVerificationRepository.

Covers the file layout, Pydantic round-trip, CRUD semantics,
versioned CAS behavior, and Protocol conformance. The service-level
behaviour (``mark_token_used`` lock + retry loop, ``verify_email``
orchestration, ``secrets.compare_digest``) is exercised by
``tests/unit/test_email_verification.py``.
"""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.concurrency import ConcurrentWriteError
from authglow.core.datetime import utcnow
from authglow.models.email_verification import EmailVerificationToken
from authglow.repositories.file.email_verification import (
    FileEmailVerificationRepository,
)
from authglow.repositories.protocols import EmailVerificationRepository


def _make_repo(test_settings) -> FileEmailVerificationRepository:
    return FileEmailVerificationRepository(settings=test_settings)


def _make_token(
    user_id: str = "user-1",
    email: str = "user-1@example.com",
    code_lookup: str = "lookup-abc",
    verification_code: str = "ABCD-EFGH-JKMN",
    *,
    used: bool = False,
    expires_at=None,
) -> EmailVerificationToken:
    return EmailVerificationToken(
        verification_code=verification_code,
        code_lookup=code_lookup,
        user_id=user_id,
        email=email,
        used=used,
        expires_at=expires_at or (utcnow() + timedelta(hours=24)),
    )


class TestFileEmailVerificationRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "email_verifications"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileEmailVerificationRepository._subdir == "email_verifications"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileEmailVerificationRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, EmailVerificationRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in (
            "create",
            "get_by_lookup",
            "update",
            "delete",
            "cleanup_expired",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileEmailVerificationRepositoryCreate:
    async def test_create_writes_file(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token()
        await repo.create(token)
        path = Path(repo._path(f"{token.code_lookup}.json"))
        assert path.exists()

    async def test_create_persists_verification_code(self, test_settings):
        """VAPT-022: the human-friendly code is on disk by design."""
        repo = _make_repo(test_settings)
        token = _make_token(code_lookup="lookup-code", verification_code="WXYZ-QRST-2345")
        await repo.create(token)
        path = Path(repo._path("lookup-code.json"))
        raw = path.read_bytes()
        assert b"WXYZ-QRST-2345" in raw

    async def test_create_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        t1 = _make_token(user_id="u-1", code_lookup="lookup-ow")
        t2 = _make_token(user_id="u-2", code_lookup="lookup-ow")
        await repo.create(t1)
        await repo.create(t2)
        result = await repo.get_by_lookup("lookup-ow")
        assert result.user_id == "u-2"


class TestFileEmailVerificationRepositoryGetByLookup:
    async def test_get_returns_token(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token()
        await repo.create(token)
        result = await repo.get_by_lookup(token.code_lookup)
        assert result is not None
        assert result.user_id == token.user_id
        assert result.email == token.email
        assert result.code_lookup == token.code_lookup
        assert result.verification_code == token.verification_code
        assert result.token_id == token.token_id

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_lookup("nonexistent")
        assert result is None

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.write_text("{not valid json")
        result = await repo.get_by_lookup("corrupt")
        assert result is None

    async def test_get_returns_none_for_invalid_pydantic(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("bad.json"))
        path.write_text('{"user_id": "u"}')
        result = await repo.get_by_lookup("bad")
        assert result is None


class TestFileEmailVerificationRepositoryUpdate:
    async def test_update_first_time_succeeds(self, test_settings):
        """First update after create: file has no _version field,
        read_json_versioned returns 0, write_json_versioned accepts
        expected=0 and writes _version=1."""
        repo = _make_repo(test_settings)
        token = _make_token()
        await repo.create(token)
        token.used = True
        await repo.update(token)
        result = await repo.get_by_lookup(token.code_lookup)
        assert result.used is True

    async def test_update_persists_changes(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(code_lookup="lookup-upd")
        await repo.create(token)
        token.used = True
        token.used_at = utcnow()
        await repo.update(token)
        result = await repo.get_by_lookup("lookup-upd")
        assert result.used is True
        assert result.used_at is not None

    async def test_update_raises_concurrent_write_error_on_stale_version(self, test_settings):
        """Simulate a cross-process race: another process increments
        the _version between our read and our write. The service
        layer's retry loop is what catches and retries this."""
        repo = _make_repo(test_settings)
        token = _make_token(code_lookup="lookup-cas")
        await repo.create(token)

        # First update: brings _version to 1.
        await repo.update(token)

        # Manually re-write the file with a higher version to simulate
        # a concurrent process winning the race.
        path = Path(repo._path("lookup-cas.json"))
        data = json.loads(path.read_text())
        data["_version"] = 5
        path.write_text(json.dumps(data))

        # Our update reads version=5, then tries to write with
        # expected=5... actually it reads 5 and writes 6. So no error.
        # To trigger the CAS error, we need to interleave: read (5),
        # then someone else writes 6, then we try to write 5.
        # Patch read_json_versioned to return a stale version.
        original_read = repo._read_json_versioned

        async def stale_read(path_arg):
            data, current_version = await original_read(path_arg)
            return data, 3  # stale: disk has 5 (or 6 after our previous update)

        with patch.object(repo, "_read_json_versioned", side_effect=stale_read):
            try:
                await repo.update(token)
            except ConcurrentWriteError:
                return
        raise AssertionError("expected ConcurrentWriteError on stale version")


class TestFileEmailVerificationRepositoryDelete:
    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token()
        await repo.create(token)
        path = Path(repo._path(f"{token.code_lookup}.json"))
        assert path.exists()
        await repo.delete(token.code_lookup)
        assert not path.exists()

    async def test_delete_nonexistent_is_noop(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.delete("nope")
        assert True


class TestFileEmailVerificationRepositoryCleanupExpired:
    async def test_cleanup_deletes_expired(self, test_settings):
        repo = _make_repo(test_settings)
        expired = _make_token(
            code_lookup="lookup-exp", expires_at=utcnow() - timedelta(hours=1)
        )
        valid = _make_token(code_lookup="lookup-ok")
        await repo.create(expired)
        await repo.create(valid)
        deleted = await repo.cleanup_expired()
        assert deleted == 1
        assert await repo.get_by_lookup("lookup-exp") is None
        assert await repo.get_by_lookup("lookup-ok") is not None

    async def test_cleanup_returns_zero_when_nothing_to_delete(self, test_settings):
        repo = _make_repo(test_settings)
        valid = _make_token(code_lookup="lookup-only-valid")
        await repo.create(valid)
        deleted = await repo.cleanup_expired()
        assert deleted == 0

    async def test_cleanup_empty_dir(self, test_settings):
        repo = _make_repo(test_settings)
        deleted = await repo.cleanup_expired()
        assert deleted == 0

    async def test_cleanup_skips_corrupt_files(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt-cleanup.json"))
        path.write_text("garbage")
        deleted = await repo.cleanup_expired()
        assert deleted == 0


class TestFileEmailVerificationRepositoryWithPatchedSettings:
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
            repo = FileEmailVerificationRepository()
            assert Path(repo._storage_path).exists()
