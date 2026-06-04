import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.user import User
from authglow.services.password import hash_password


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestCreateVerificationToken:
    def test_create_token(self, email_verification_service):
        user = User(
            id="user-ev-1",
            email="ev1@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        assert token is not None
        assert token.user_id == "user-ev-1"
        assert token.email == "ev1@example.com"
        assert token.used is False
        assert len(token.token) > 20

    def test_token_not_uuid(self, email_verification_service):
        import re

        user = User(
            id="user-ev-uuid",
            email="ev-uuid@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assert not uuid_pattern.match(token.token)


class TestGetToken:
    def test_get_token(self, email_verification_service):
        user = User(
            id="user-ev-get",
            email="ev-get@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        retrieved = asyncio_run(email_verification_service.get_token(token.token))
        assert retrieved is not None
        assert retrieved.token == token.token

    def test_get_token_not_found(self, email_verification_service):
        result = asyncio_run(email_verification_service.get_token("nonexistent"))
        assert result is None


class TestMarkTokenUsed:
    def test_mark_token_used(self, email_verification_service):
        user = User(
            id="user-ev-mark",
            email="ev-mark@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        result = asyncio_run(email_verification_service.mark_token_used(token.token))
        assert result is True
        retrieved = asyncio_run(email_verification_service.get_token(token.token))
        assert retrieved.used is True

    def test_mark_token_used_twice_fails(self, email_verification_service):
        user = User(
            id="user-ev-twice",
            email="ev-twice@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        result1 = asyncio_run(email_verification_service.mark_token_used(token.token))
        result2 = asyncio_run(email_verification_service.mark_token_used(token.token))
        assert result1 is True
        assert result2 is False

    def test_mark_nonexistent_token_fails(self, email_verification_service):
        result = asyncio_run(email_verification_service.mark_token_used("nonexistent"))
        assert result is False


class TestVerifyEmail:
    def test_verify_email_success(self, email_verification_service):
        user = User(
            id="user-ev-verify",
            email="ev-verify@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        email_verification_service.user_storage.get_user = AsyncMock(return_value=user)
        email_verification_service.user_storage.update_user = AsyncMock()

        token = asyncio_run(email_verification_service.create_verification_token(user))
        success, error = asyncio_run(email_verification_service.verify_email(token.token))
        assert success is True
        assert error is None

    def test_verify_email_invalid_token(self, email_verification_service):
        success, error = asyncio_run(email_verification_service.verify_email("invalid-token"))
        assert success is False
        assert "Invalid" in error

    def test_verify_email_used_token(self, email_verification_service):
        user = User(
            id="user-ev-used",
            email="ev-used@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        email_verification_service.user_storage.get_user = AsyncMock(return_value=user)

        token = asyncio_run(email_verification_service.create_verification_token(user))
        asyncio_run(email_verification_service.mark_token_used(token.token))
        success, error = asyncio_run(email_verification_service.verify_email(token.token))
        assert success is False
        assert "already used" in error

    def test_verify_email_expired_token(self, email_verification_service):
        import json
        from datetime import timedelta

        user = User(
            id="user-ev-expired",
            email="ev-expired@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        path = f"{email_verification_service.storage_path}/{token.token_lookup}.json"
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(hours=1)).isoformat()
        with email_verification_service.fs.open(path, "w") as f:
            json.dump(data, f)

        success, error = asyncio_run(email_verification_service.verify_email(token.token))
        assert success is False
        assert "expired" in error.lower()

    def test_verify_email_user_not_found(self, email_verification_service):
        user = User(
            id="user-ev-nf",
            email="ev-nf@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        email_verification_service.user_storage.get_user = AsyncMock(return_value=None)

        token = asyncio_run(email_verification_service.create_verification_token(user))
        success, error = asyncio_run(email_verification_service.verify_email(token.token))
        assert success is False
        assert "not found" in error.lower()


class TestHashedTokenStorage:
    """VAPT-003: Plaintext token must never be on disk."""

    def test_plaintext_not_on_disk(self, email_verification_service):
        user = User(
            id="user-ev-hash",
            email="ev-hash@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))

        assert token.token is not None
        pat = f"{email_verification_service.storage_path}/*.json"
        files = email_verification_service.fs.glob(pat)
        raw = b""
        for fp in files:
            raw += email_verification_service.fs.cat(fp)

        assert token.token.encode() not in raw
        assert token.token_hash.encode() in raw


class TestCleanupExpiredTokens:
    def test_cleanup_expired_tokens(self, email_verification_service):
        import json
        from datetime import timedelta

        user = User(
            id="user-ev-cleanup",
            email="ev-cleanup@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        path = f"{email_verification_service.storage_path}/{token.token_lookup}.json"
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(hours=25)).isoformat()
        with email_verification_service.fs.open(path, "w") as f:
            json.dump(data, f)

        deleted = asyncio_run(email_verification_service.cleanup_expired_tokens())
        assert deleted >= 1


class TestNoTokenInAuditLog:
    """VAPT-011: Plaintext token must never appear in audit log metadata."""

    def test_verify_email_api_does_not_log_token(self):
        import inspect
        from authglow.api.email_verification import verify_email_api

        source = inspect.getsource(verify_email_api)
        assert '"token":' not in source
