"""Unit tests for the FileSessionRepository.

Covers MFA + consent-session file layout, JSON round-trip, Pydantic
model reconstruction, dict round-trip, missing-file semantics, and
Protocol conformance. The service-level behaviour (HMAC lookup,
expiry sweep, plaintext token re-injection) is exercised by
``tests/unit/test_session.py``.
"""

from datetime import timedelta
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.session import MFASession
from authglow.repositories.file.session import FileSessionRepository
from authglow.repositories.protocols import SessionRepository


def _make_repo(test_settings) -> FileSessionRepository:
    return FileSessionRepository(settings=test_settings)


class TestFileSessionRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "sessions"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileSessionRepository._subdir == "sessions"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileSessionRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, SessionRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in (
            "save_mfa_session",
            "get_mfa_session",
            "delete_mfa_session",
            "save_consent_session",
            "get_consent_session",
            "delete_consent_session",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileSessionRepositoryMFASessions:
    async def test_save_creates_file(self, test_settings):
        repo = _make_repo(test_settings)
        session = _make_mfa_session()
        await repo.save_mfa_session(session)
        path = Path(repo._path(f"{session.token_lookup}.json"))
        assert path.exists()

    async def test_get_returns_session(self, test_settings):
        repo = _make_repo(test_settings)
        session = _make_mfa_session()
        await repo.save_mfa_session(session)
        result = await repo.get_mfa_session(session.token_lookup)
        assert result is not None
        assert result.user_id == session.user_id
        assert result.client_id == session.client_id
        assert result.token_lookup == session.token_lookup

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_mfa_session("nonexistent-lookup")
        assert result is None

    async def test_save_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        s1 = _make_mfa_session(user_id="user-1")
        s2 = _make_mfa_session(user_id="user-2", token_lookup=s1.token_lookup)
        await repo.save_mfa_session(s1)
        await repo.save_mfa_session(s2)
        result = await repo.get_mfa_session(s1.token_lookup)
        assert result.user_id == "user-2"

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("corrupt.json"))
        path.write_text("not json")
        result = await repo.get_mfa_session("corrupt")
        assert result is None

    async def test_get_returns_none_for_invalid_pydantic(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("bad.json"))
        path.write_text('{"user_id": "u"}')
        result = await repo.get_mfa_session("bad")
        assert result is None

    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        session = _make_mfa_session()
        await repo.save_mfa_session(session)
        path = Path(repo._path(f"{session.token_lookup}.json"))
        assert path.exists()
        await repo.delete_mfa_session(session.token_lookup)
        assert not path.exists()

    async def test_delete_nonexistent_is_noop(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.delete_mfa_session("nope")
        assert True


class TestFileSessionRepositoryConsentSessions:
    async def test_save_creates_file_with_consent_prefix(self, test_settings):
        repo = _make_repo(test_settings)
        data = _make_consent_dict()
        await repo.save_consent_session(data)
        path = Path(repo._path(f"consent_{data['token_lookup']}.json"))
        assert path.exists()

    async def test_get_returns_dict(self, test_settings):
        repo = _make_repo(test_settings)
        data = _make_consent_dict()
        await repo.save_consent_session(data)
        result = await repo.get_consent_session(data["token_lookup"])
        assert result is not None
        assert result["user_id"] == data["user_id"]
        assert result["client_id"] == data["client_id"]
        assert result["session_token"] == data["session_token"]

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        result = await repo.get_consent_session("nonexistent")
        assert result is None

    async def test_save_requires_token_lookup(self, test_settings):
        repo = _make_repo(test_settings)
        bad: Dict[str, Any] = {"user_id": "u", "client_id": "c"}
        try:
            await repo.save_consent_session(bad)
        except ValueError:
            return
        raise AssertionError("expected ValueError when 'token_lookup' is missing")

    async def test_save_overwrites(self, test_settings):
        repo = _make_repo(test_settings)
        d1 = _make_consent_dict(user_id="u-1")
        d2 = _make_consent_dict(user_id="u-2", token_lookup=d1["token_lookup"])
        await repo.save_consent_session(d1)
        await repo.save_consent_session(d2)
        result = await repo.get_consent_session(d1["token_lookup"])
        assert result["user_id"] == "u-2"

    async def test_get_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("consent_corrupt.json"))
        path.write_text("garbage")
        result = await repo.get_consent_session("corrupt")
        assert result is None

    async def test_delete_removes_file(self, test_settings):
        repo = _make_repo(test_settings)
        data = _make_consent_dict()
        await repo.save_consent_session(data)
        path = Path(repo._path(f"consent_{data['token_lookup']}.json"))
        assert path.exists()
        await repo.delete_consent_session(data["token_lookup"])
        assert not path.exists()

    async def test_delete_nonexistent_is_noop(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.delete_consent_session("nope")
        assert True


class TestFileSessionRepositoryIndependence:
    async def test_mfa_and_consent_paths_dont_collide(self, test_settings):
        repo = _make_repo(test_settings)
        session = _make_mfa_session()
        consent = _make_consent_dict(token_lookup=session.token_lookup)
        await repo.save_mfa_session(session)
        await repo.save_consent_session(consent)
        mfa_result = await repo.get_mfa_session(session.token_lookup)
        consent_result = await repo.get_consent_session(session.token_lookup)
        assert mfa_result.user_id == session.user_id
        assert consent_result["user_id"] == consent["user_id"]
        assert consent_result["session_token"] == consent["session_token"]


class TestFileSessionRepositoryWithPatchedSettings:
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
            repo = FileSessionRepository()
            assert Path(repo._storage_path).exists()


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_mfa_session(
    user_id: str = "user-1",
    client_id: str = "client-1",
    token_lookup: str = "lookup-abc",
) -> MFASession:
    return MFASession(
        session_token="plaintext-xyz",
        token_lookup=token_lookup,
        user_id=user_id,
        client_id=client_id,
        redirect_uri="https://example.com/cb",
        scope="read",
        state=None,
        code_challenge=None,
        code_challenge_method=None,
        nonce=None,
        expires_at=utcnow() + timedelta(minutes=5),
    )


def _make_consent_dict(
    user_id: str = "user-1",
    client_id: str = "client-1",
    token_lookup: str = "consent-lookup-1",
) -> Dict[str, Any]:
    return {
        "session_token": "plaintext-consent-xyz",
        "token_lookup": token_lookup,
        "user_id": user_id,
        "client_id": client_id,
        "redirect_uri": "https://example.com/cb",
        "scope": "read",
        "state": None,
        "code_challenge": None,
        "code_challenge_method": None,
        "nonce": None,
        "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
    }
