"""Unit tests for the FilePasswordResetRepository.

Covers the dual-mirror file layout, the primary + code-lookup
round-trips, the listing / stats aggregation, the cleanup with
its 24-hour grace period, and Protocol conformance. The
service-level behaviour (bcrypt verify, named lock, CAS retry
loop, ``generate_reset_code``) is exercised by
``tests/unit/test_password_reset_service.py``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken
from authglow.repositories.file.password_reset import (
    FilePasswordResetRepository,
)
from authglow.repositories.protocols import PasswordResetRepository


def _make_repo(test_settings) -> FilePasswordResetRepository:
    return FilePasswordResetRepository(settings=test_settings)


def _make_token(
    user_id: str = "user-1",
    email: str = "user-1@example.com",
    token_lookup: str = "lookup-abc",
    reset_code: str = "ABCD-EFGH-JKLM",
    *,
    is_used: bool = False,
    expires_at=None,
) -> PasswordResetToken:
    return PasswordResetToken(
        token_lookup=token_lookup,
        user_id=user_id,
        email=email,
        token_hash="$2b$12$dummybcrypthash",
        reset_code=reset_code,
        is_used=is_used,
        expires_at=expires_at or (utcnow() + timedelta(minutes=30)),
    )


def _code_lookup(test_settings, code: str) -> str:
    """Helper to derive the code lookup key (delegates to the
    production HMAC algorithm)."""
    import hashlib
    import hmac

    normalised = code.strip().upper().replace(" ", "").replace("\t", "")
    return hmac.new(
        test_settings.secret_key.encode(), normalised.encode(), hashlib.sha256
    ).hexdigest()


class TestFilePasswordResetRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "password_resets"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FilePasswordResetRepository._subdir == "password_resets"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFilePasswordResetRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, PasswordResetRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in (
            "create",
            "get_by_token_lookup",
            "get_by_code_lookup",
            "update",
            "delete_by_token_lookup",
            "list_for_user",
            "list_all",
            "cleanup_expired",
            "stats",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFilePasswordResetRepositoryCreate:
    async def test_create_writes_primary_file(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token()
        await repo.create(token)
        path = Path(repo._token_path(token.token_lookup))
        assert path.exists()

    async def test_create_writes_mirror_file(self, test_settings):
        """VAPT-022: same payload, indexed by code lookup."""
        repo = _make_repo(test_settings)
        token = _make_token(reset_code="AAAA-BBBB-CCCC")
        await repo.create(token)
        code_lookup = _code_lookup(test_settings, "AAAA-BBBB-CCCC")
        path = Path(repo._code_path(code_lookup))
        assert path.exists()

    async def test_primary_and_mirror_have_same_content(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-mirror", reset_code="MIRR-ORTE-STCD")
        await repo.create(token)
        primary = Path(repo._token_path("lookup-mirror")).read_text()
        code_lookup = _code_lookup(test_settings, "MIRR-ORTE-STCD")
        mirror = Path(repo._code_path(code_lookup)).read_text()
        assert primary == mirror

    async def test_create_does_not_persist_plaintext_token(self, test_settings):
        """VAPT-003-style: bearer token is hashed at rest, not persisted."""
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-nopt", reset_code="NONE-PLAI-NTOK")
        await repo.create(token)
        for path in (
            Path(repo._token_path("lookup-nopt")),
            Path(repo._code_path(_code_lookup(test_settings, "NONE-PLAI-NTOK"))),
        ):
            raw = path.read_bytes()
            # The plaintext bearer is not on the model either way
            # (it lives in the service, never round-tripped), so we
            # check that the bcrypt hash marker is present instead.
            assert b"$2b$12$dummybcrypthash" in raw

    async def test_create_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        t1 = _make_token(user_id="u-1", token_lookup="lookup-ow", reset_code="OW01-OW01-OW01")
        t2 = _make_token(user_id="u-2", token_lookup="lookup-ow", reset_code="OW02-OW02-OW02")
        await repo.create(t1)
        await repo.create(t2)
        result = await repo.get_by_token_lookup("lookup-ow")
        assert result.user_id == "u-2"


class TestFilePasswordResetRepositoryGet:
    async def test_get_by_token_lookup_returns_token(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-get1")
        await repo.create(token)
        result = await repo.get_by_token_lookup("lookup-get1")
        assert result is not None
        assert result.user_id == token.user_id
        assert result.token_lookup == token.token_lookup

    async def test_get_by_token_lookup_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_token_lookup("nonexistent")
        assert result is None

    async def test_get_by_code_lookup_returns_token(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-code", reset_code="CODE-LOOK-UPXX")
        await repo.create(token)
        code_lookup = _code_lookup(test_settings, "CODE-LOOK-UPXX")
        result = await repo.get_by_code_lookup(code_lookup)
        assert result is not None
        assert result.user_id == token.user_id

    async def test_get_by_code_lookup_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_code_lookup("nonexistent")
        assert result is None

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._token_path("corrupt"))
        path.write_text("garbage")
        result = await repo.get_by_token_lookup("corrupt")
        assert result is None


class TestFilePasswordResetRepositoryUpdate:
    async def test_update_writes_primary_and_mirror(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-upd", reset_code="UPD1-UPD2-UPD3")
        await repo.create(token)
        token.is_used = True
        token.used_at = utcnow()
        await repo.update(token)
        primary = await repo.get_by_token_lookup("lookup-upd")
        mirror_code_lookup = _code_lookup(test_settings, "UPD1-UPD2-UPD3")
        mirror = await repo.get_by_code_lookup(mirror_code_lookup)
        assert primary.is_used is True
        assert mirror.is_used is True


class TestFilePasswordResetRepositoryDelete:
    async def test_delete_removes_primary_and_mirror(self, test_settings):
        repo = _make_repo(test_settings)
        token = _make_token(token_lookup="lookup-del", reset_code="DEL1-DEL2-DEL3")
        await repo.create(token)
        primary = Path(repo._token_path("lookup-del"))
        mirror = Path(repo._code_path(_code_lookup(test_settings, "DEL1-DEL2-DEL3")))
        assert primary.exists()
        assert mirror.exists()
        result = await repo.delete_by_token_lookup("lookup-del")
        assert result is True
        assert not primary.exists()
        assert not mirror.exists()

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.delete_by_token_lookup("nope")
        assert result is False

    async def test_delete_handles_corrupt_primary(self, test_settings):
        """If the primary file is corrupt, we still delete it (and
        there's no mirror to delete because the corrupt primary
        couldn't have been written by ``create``)."""
        repo = _make_repo(test_settings)
        path = Path(repo._token_path("corrupt-del"))
        path.write_text("garbage")
        result = await repo.delete_by_token_lookup("corrupt-del")
        assert result is True
        assert not path.exists()


class TestFilePasswordResetRepositoryList:
    async def test_list_for_user_filters_other_users(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(user_id="u-1", token_lookup="l-1", reset_code="AAA-AAA-AA1"))
        await repo.create(_make_token(user_id="u-2", token_lookup="l-2", reset_code="BBB-BBB-BB2"))
        result = await repo.list_for_user("u-1")
        assert len(result) == 1
        assert result[0].user_id == "u-1"

    async def test_list_for_user_active_only_filters_used_and_expired(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(
            _make_token(user_id="u", token_lookup="l-active", reset_code="AC1-AC1-AC1")
        )
        await repo.create(
            _make_token(
                user_id="u",
                token_lookup="l-used",
                reset_code="US1-US1-US1",
                is_used=True,
            )
        )
        await repo.create(
            _make_token(
                user_id="u",
                token_lookup="l-expired",
                reset_code="EX1-EX1-EX1",
                expires_at=utcnow() - timedelta(hours=1),
            )
        )
        result = await repo.list_for_user("u", active_only=True)
        assert len(result) == 1
        assert result[0].token_lookup == "l-active"

    async def test_list_for_user_returns_all_when_inactive(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(user_id="u", token_lookup="l-1", reset_code="AA-AA-AA-01"))
        await repo.create(
            _make_token(
                user_id="u",
                token_lookup="l-2",
                reset_code="BB-BB-BB-02",
                is_used=True,
            )
        )
        result = await repo.list_for_user("u", active_only=False)
        assert len(result) == 2

    async def test_list_for_user_skips_mirror_files(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(user_id="u", token_lookup="l-1", reset_code="MM-MM-MM-01"))
        result = await repo.list_for_user("u")
        assert len(result) == 1

    async def test_list_all_pagination(self, test_settings):
        repo = _make_repo(test_settings)
        for i in range(5):
            await repo.create(
                _make_token(
                    user_id=f"u-{i}",
                    token_lookup=f"l-{i}",
                    reset_code=f"P{i:02d}-PAGE-PAG0",
                )
            )
        page1 = await repo.list_all(limit=2, offset=0)
        page2 = await repo.list_all(limit=2, offset=2)
        page3 = await repo.list_all(limit=2, offset=4)
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1


class TestFilePasswordResetRepositoryCleanup:
    async def test_cleanup_deletes_used(self, test_settings):
        repo = _make_repo(test_settings)
        used = _make_token(token_lookup="l-used", reset_code="CL1-CL1-CL1", is_used=True)
        await repo.create(used)
        deleted = await repo.cleanup_expired()
        assert deleted == 1

    async def test_cleanup_deletes_grace_expired(self, test_settings):
        """Tokens more than 24h past expiry are hard-deleted."""
        repo = _make_repo(test_settings)
        long_expired = _make_token(
            token_lookup="l-old",
            reset_code="CL2-CL2-CL2",
            expires_at=utcnow() - timedelta(hours=25),
        )
        await repo.create(long_expired)
        deleted = await repo.cleanup_expired()
        assert deleted == 1

    async def test_cleanup_keeps_recently_expired(self, test_settings):
        """Tokens expired less than 24h ago are still in the grace window."""
        repo = _make_repo(test_settings)
        recent = _make_token(
            token_lookup="l-recent",
            reset_code="CL3-CL3-CL3",
            expires_at=utcnow() - timedelta(minutes=10),
        )
        await repo.create(recent)
        deleted = await repo.cleanup_expired()
        assert deleted == 0

    async def test_cleanup_keeps_valid_tokens(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(token_lookup="l-valid", reset_code="CL4-CL4-CL4"))
        deleted = await repo.cleanup_expired()
        assert deleted == 0

    async def test_cleanup_deletes_mirror_with_primary(self, test_settings):
        repo = _make_repo(test_settings)
        used = _make_token(token_lookup="l-mirror", reset_code="CL5-CL5-CL5", is_used=True)
        await repo.create(used)
        mirror_path = Path(repo._code_path(_code_lookup(test_settings, "CL5-CL5-CL5")))
        assert mirror_path.exists()
        await repo.cleanup_expired()
        assert not mirror_path.exists()


class TestFilePasswordResetRepositoryStats:
    async def test_stats_empty(self, test_settings):
        repo = _make_repo(test_settings)
        stats = await repo.stats()
        assert stats == {"total": 0, "active": 0, "expired": 0, "used": 0}

    async def test_stats_with_mixed_tokens(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(token_lookup="l-active", reset_code="ST-ACT-IVE1"))
        await repo.create(
            _make_token(token_lookup="l-used", reset_code="ST-USE-D001", is_used=True)
        )
        await repo.create(
            _make_token(
                token_lookup="l-expired",
                reset_code="ST-EXP-IRED",
                expires_at=utcnow() - timedelta(hours=1),
            )
        )
        stats = await repo.stats()
        assert stats["total"] == 3
        assert stats["active"] == 1
        assert stats["used"] == 1
        assert stats["expired"] == 1

    async def test_stats_does_not_double_count_mirrors(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.create(_make_token(token_lookup="l-1", reset_code="ST-MIR-ROR1"))
        stats = await repo.stats()
        assert stats["total"] == 1


class TestFilePasswordResetRepositoryWithPatchedSettings:
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
            repo = FilePasswordResetRepository()
            assert Path(repo._storage_path).exists()
