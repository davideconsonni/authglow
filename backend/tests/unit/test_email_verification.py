import re
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


_VERIFICATION_CODE_REGEX = re.compile(
    r"^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$"
)


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
        assert _VERIFICATION_CODE_REGEX.match(token.verification_code)
        assert len(token.verification_code) == 14
        assert len(token.code_lookup) == 64

    def test_token_not_uuid(self, email_verification_service):
        user = User(
            id="user-ev-uuid",
            email="ev-uuid@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        uuid_pattern = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        assert not uuid_pattern.match(token.verification_code)

    def test_code_alphabet_excludes_confusable_chars(self, email_verification_service):
        user = User(
            id="user-ev-alpha",
            email="ev-alpha@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        for _ in range(50):
            token = asyncio_run(email_verification_service.create_verification_token(user))
            for ch in token.verification_code:
                if ch == "-":
                    continue
                assert ch not in "01OIL", (
                    f"verification_code {token.verification_code!r} contains confusable {ch!r}"
                )


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
        retrieved = asyncio_run(email_verification_service.get_token(token.verification_code))
        assert retrieved is not None
        assert retrieved.code_lookup == token.code_lookup
        assert retrieved.verification_code == token.verification_code

    def test_get_token_normalises_whitespace_and_case(self, email_verification_service):
        user = User(
            id="user-ev-norm",
            email="ev-norm@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        lowercase = token.verification_code.lower()
        retrieved = asyncio_run(email_verification_service.get_token(lowercase))
        assert retrieved is not None
        assert retrieved.code_lookup == token.code_lookup

    def test_get_token_with_whitespace(self, email_verification_service):
        user = User(
            id="user-ev-ws",
            email="ev-ws@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        padded = f"  {token.verification_code}\t"
        retrieved = asyncio_run(email_verification_service.get_token(padded))
        assert retrieved is not None

    def test_get_token_not_found(self, email_verification_service):
        result = asyncio_run(email_verification_service.get_token("AAAA-BBBB-CCCC"))
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
        result = asyncio_run(email_verification_service.mark_token_used(token.verification_code))
        assert result is True
        retrieved = asyncio_run(email_verification_service.get_token(token.verification_code))
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
        result1 = asyncio_run(email_verification_service.mark_token_used(token.verification_code))
        result2 = asyncio_run(email_verification_service.mark_token_used(token.verification_code))
        assert result1 is True
        assert result2 is False

    def test_mark_nonexistent_token_fails(self, email_verification_service):
        result = asyncio_run(email_verification_service.mark_token_used("AAAA-BBBB-CCCC"))
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
        success, error = asyncio_run(
            email_verification_service.verify_email(token.verification_code)
        )
        assert success is True
        assert error is None
        assert user.email_verified is True

    def test_verify_email_invalid_code(self, email_verification_service):
        success, error = asyncio_run(email_verification_service.verify_email("AAAA-BBBB-CCCC"))
        assert success is False
        assert "Invalid" in error

    def test_verify_email_used_code(self, email_verification_service):
        user = User(
            id="user-ev-used",
            email="ev-used@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        email_verification_service.user_storage.get_user = AsyncMock(return_value=user)

        token = asyncio_run(email_verification_service.create_verification_token(user))
        asyncio_run(email_verification_service.mark_token_used(token.verification_code))
        success, error = asyncio_run(
            email_verification_service.verify_email(token.verification_code)
        )
        assert success is False
        assert "already used" in error

    def test_verify_email_expired_code(self, email_verification_service):
        import json

        user = User(
            id="user-ev-expired",
            email="ev-expired@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        path = f"{email_verification_service.repository._storage_path}/{token.code_lookup}.json"
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(hours=1)).isoformat()
        with email_verification_service.repository._filesystem.open(path, "w") as f:
            json.dump(data, f)

        success, error = asyncio_run(
            email_verification_service.verify_email(token.verification_code)
        )
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
        success, error = asyncio_run(
            email_verification_service.verify_email(token.verification_code)
        )
        assert success is False
        assert "not found" in error.lower()


class TestVerificationCodeOnDisk:
    """VAPT-022 alignment: the human-friendly code is stored in plaintext
    in the JSON body (single-use, 24h window, HMAC-as-filename). The
    bcrypt-hashed bearer token is gone — the security model is now
    identical to the password-reset flow.
    """

    def test_verification_code_is_on_disk_by_design(self, email_verification_service):
        user = User(
            id="user-ev-hash",
            email="ev-hash@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))

        pat = f"{email_verification_service.repository._storage_path}/*.json"
        files = email_verification_service.repository._filesystem.glob(pat)
        assert files, "expected at least one on-disk verification file"
        raw = b""
        for fp in files:
            raw += email_verification_service.repository._filesystem.cat(fp)
        assert token.verification_code.encode() in raw, (
            "verification_code must be present on disk (VAPT-022 dual-mirror style)"
        )

    def test_token_id_is_on_disk(self, email_verification_service):
        user = User(
            id="user-ev-tid",
            email="ev-tid@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        pat = f"{email_verification_service.repository._storage_path}/*.json"
        files = email_verification_service.repository._filesystem.glob(pat)
        raw = b""
        for fp in files:
            raw += email_verification_service.repository._filesystem.cat(fp)
        assert token.token_id.encode() in raw, "token_id should be persisted for audit joinability"


class TestCleanupExpiredTokens:
    def test_cleanup_expired_tokens(self, email_verification_service):
        import json

        user = User(
            id="user-ev-cleanup",
            email="ev-cleanup@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=False,
        )
        token = asyncio_run(email_verification_service.create_verification_token(user))
        path = f"{email_verification_service.repository._storage_path}/{token.code_lookup}.json"
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(hours=25)).isoformat()
        with email_verification_service.repository._filesystem.open(path, "w") as f:
            json.dump(data, f)

        deleted = asyncio_run(email_verification_service.cleanup_expired_tokens())
        assert deleted >= 1


class TestNoTokenInAuditLog:
    """VAPT-011: Plaintext code must never appear in audit log metadata."""

    def test_verify_email_api_does_not_log_token(self):
        import inspect
        from authglow.api.email_verification import verify_email_api

        source = inspect.getsource(verify_email_api)
        assert '"token":' not in source
        assert '"verification_code":' not in source
