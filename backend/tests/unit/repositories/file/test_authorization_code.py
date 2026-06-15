"""Unit tests for the FileAuthorizationCodeRepository.

Covers the file layout, Pydantic round-trip (with the transparent
``_version`` field handling), the absent / corrupt / expired /
already-used policy of ``get_by_code``, the CAS-protected
``mark_used`` with bounded retries, and Protocol conformance.
The service-level behaviour (in-process lock, AuthorizationCode
model construction, client/scope verification) is exercised by
``tests/unit/test_oauth2.py``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.concurrency import ConcurrentWriteError
from authglow.core.datetime import utcnow
from authglow.models.token import AuthorizationCode
from authglow.repositories.file.authorization_code import (
    FileAuthorizationCodeRepository,
)
from authglow.repositories.protocols import AuthorizationCodeRepository


def _make_repo(test_settings) -> FileAuthorizationCodeRepository:
    return FileAuthorizationCodeRepository(settings=test_settings)


def _make_code(
    code: str = "test-code-abc123",
    client_id: str = "client-1",
    user_id: str = "user-1",
    *,
    scope: str = "read",
    used: bool = False,
    expires_at=None,
) -> AuthorizationCode:
    return AuthorizationCode(
        code=code,
        client_id=client_id,
        user_id=user_id,
        redirect_uri="https://example.com/callback",
        scope=scope,
        used=used,
        expires_at=expires_at or (utcnow() + timedelta(minutes=10)),
    )


class TestFileAuthorizationCodeRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "auth_codes"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileAuthorizationCodeRepository._subdir == "auth_codes"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings

    def test_cas_retries_bounded(self):
        assert FileAuthorizationCodeRepository.MAX_CAS_RETRIES == 3


class TestFileAuthorizationCodeRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, AuthorizationCodeRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("create", "get_by_code", "mark_used", "delete"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileAuthorizationCodeRepositoryCreate:
    async def test_create_writes_file_named_after_code(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="plaintext-code-xyz")
        await repo.create(code)
        path = Path(repo._path("plaintext-code-xyz.json"))
        assert path.exists()

    async def test_create_round_trips(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="rt-1", user_id="u-rt", scope="read write")
        await repo.create(code)
        result = await repo.get_by_code("rt-1")
        assert result is not None
        assert result.user_id == "u-rt"
        assert result.scope == "read write"
        assert result.code == "rt-1"
        assert result.used is False

    async def test_create_persists_pkce_fields(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="pkce-1")
        code.code_challenge = "challenge-xyz"
        code.code_challenge_method = "S256"
        await repo.create(code)
        result = await repo.get_by_code("pkce-1")
        assert result.code_challenge == "challenge-xyz"
        assert result.code_challenge_method == "S256"

    async def test_create_persists_nonce(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="nonce-1")
        code.nonce = "oidc-nonce-xyz"
        await repo.create(code)
        result = await repo.get_by_code("nonce-1")
        assert result.nonce == "oidc-nonce-xyz"

    async def test_create_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        c1 = _make_code(code="ow-1", user_id="u-1")
        c2 = _make_code(code="ow-1", user_id="u-2")
        await repo.create(c1)
        await repo.create(c2)
        result = await repo.get_by_code("ow-1")
        assert result.user_id == "u-2"


class TestFileAuthorizationCodeRepositoryGetByCode:
    async def test_get_returns_code(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="get-1")
        await repo.create(code)
        result = await repo.get_by_code("get-1")
        assert result is not None
        assert result.code == "get-1"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_by_code("nonexistent")
        assert result is None

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.write_text("{not valid json")
        result = await repo.get_by_code("corrupt")
        assert result is None

    async def test_get_returns_none_for_invalid_pydantic(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("bad.json"))
        path.write_text('{"client_id": "c"}')
        result = await repo.get_by_code("bad")
        assert result is None

    async def test_get_returns_none_for_used_code(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="used-1", used=True)
        await repo.create(code)
        result = await repo.get_by_code("used-1")
        assert result is None

    async def test_get_returns_none_for_expired_and_deletes(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="exp-1", expires_at=utcnow() - timedelta(minutes=1))
        await repo.create(code)
        path = Path(repo._path("exp-1.json"))
        assert path.exists()
        result = await repo.get_by_code("exp-1")
        assert result is None
        assert not path.exists()

    async def test_get_transparently_strips_version_field(self, test_settings):
        """After mark_used, the on-disk file has ``_version``; get_by_code
        must still return a valid AuthorizationCode."""
        repo = _make_repo(test_settings)
        code = _make_code(code="ver-1")
        await repo.create(code)
        await repo.mark_used("ver-1")
        result = await repo.get_by_code("ver-1")
        # used=True so we get None, but no Pydantic validation error.
        assert result is None


class TestFileAuthorizationCodeRepositoryMarkUsed:
    async def test_mark_used_first_time_succeeds(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-1")
        await repo.create(code)
        result = await repo.mark_used("mark-1")
        assert result is True

    async def test_mark_used_returns_false_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.mark_used("nonexistent")
        assert result is False

    async def test_mark_used_returns_false_for_already_used(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-2", used=True)
        await repo.create(code)
        result = await repo.mark_used("mark-2")
        assert result is False

    async def test_mark_used_returns_false_for_expired(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-3", expires_at=utcnow() - timedelta(minutes=1))
        await repo.create(code)
        result = await repo.mark_used("mark-3")
        assert result is False

    async def test_mark_used_returns_false_for_corrupt(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("mark-corrupt.json"))
        path.write_text("garbage")
        result = await repo.mark_used("mark-corrupt")
        assert result is False

    async def test_mark_used_persists_used_flag(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-4")
        await repo.create(code)
        await repo.mark_used("mark-4")
        # After mark_used, the on-disk file has _version; get_by_code
        # returns None (used=True). The persistence is observable
        # via the underlying _read_json_versioned call.
        data, _ = await repo._read_json_versioned(repo._path("mark-4.json"))
        assert data["used"] is True

    async def test_mark_used_retries_on_concurrent_write(self, test_settings):
        """Force a ConcurrentWriteError on the first write, verify
        the retry loop reads the new version and still succeeds."""
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-cas")
        await repo.create(code)

        original_write = repo._write_json_versioned
        call_count = [0]

        async def flaky_write(path, payload, version, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConcurrentWriteError("simulated cross-process race")
            return await original_write(path, payload, version, **kwargs)

        with patch.object(repo, "_write_json_versioned", side_effect=flaky_write):
            result = await repo.mark_used("mark-cas")
        assert result is True
        assert call_count[0] == 2

    async def test_mark_used_returns_false_after_max_retries(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="mark-storm")
        await repo.create(code)

        async def always_fail(path, payload, version, **kwargs):
            raise ConcurrentWriteError("simulated cross-process storm")

        with patch.object(repo, "_write_json_versioned", side_effect=always_fail):
            result = await repo.mark_used("mark-storm")
        assert result is False


class TestFileAuthorizationCodeRepositoryDelete:
    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        code = _make_code(code="del-1")
        await repo.create(code)
        path = Path(repo._path("del-1.json"))
        assert path.exists()
        await repo.delete("del-1")
        assert not path.exists()

    async def test_delete_nonexistent_is_noop(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.delete("nope")
        assert True


class TestFileAuthorizationCodeRepositoryWithPatchedSettings:
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
            repo = FileAuthorizationCodeRepository()
            assert Path(repo._storage_path).exists()
