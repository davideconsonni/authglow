"""Tests for CSRF token service and form protection."""

import asyncio
import json
import time
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


class TestCSRFTokenService:
    """Unit tests for CSRFTokenService."""

    def test_new_token_is_random(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            t1 = svc._new_token()
            t2 = svc._new_token()
            assert t1 != t2
            assert len(t1) >= 32

    def test_new_session_id_is_random(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            s1 = svc._new_session_id()
            s2 = svc._new_session_id()
            assert s1 != s2
            assert len(s1) >= 32

    def test_generate_token_stores_file(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-abc"
            token = asyncio_run(svc.generate_token(session_id))

            assert token is not None
            assert len(token) >= 32

            path = f"{svc.storage_path}/{session_id}.json"
            data = json.loads(svc.fs.cat(path))
            assert data["token"] == token
            assert "expires_at" in data
            assert data["expires_at"] > time.time()

    def test_validate_correct_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-validate"
            token = asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token(session_id, token))
            assert result is True

    def test_validate_wrong_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-wrong"
            asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token(session_id, "wrong-token"))
            assert result is False

    def test_validate_wrong_session(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-1"
            token = asyncio_run(svc.generate_token(session_id))

            result = asyncio_run(svc.validate_token("different-session", token))
            assert result is False

    def test_validate_nonexistent_session(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            result = asyncio_run(svc.validate_token("nonexistent", "some-token"))
            assert result is False

    def test_token_expiry(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-expired"
            token = asyncio_run(svc.generate_token(session_id))

            path = f"{svc.storage_path}/{session_id}.json"
            data = json.loads(svc.fs.cat(path))
            data["expires_at"] = time.time() - 60
            svc.fs.pipe(path, json.dumps(data).encode())

            result = asyncio_run(svc.validate_token(session_id, token))
            assert result is False

    def test_generate_replaces_existing_token(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            session_id = "test-session-replace"
            token1 = asyncio_run(svc.generate_token(session_id))
            token2 = asyncio_run(svc.generate_token(session_id))

            assert token1 != token2
            assert not asyncio_run(svc.validate_token(session_id, token1))
            assert asyncio_run(svc.validate_token(session_id, token2))


class TestCSRFOnAuthorizeRoute:
    """Tests for CSRF protection on POST /oauth2/authorize."""

    @pytest.fixture(autouse=True)
    def _disable_limiter(self):
        from authglow.core.rate_limit import limiter

        limiter.enabled = False
        yield
        limiter.enabled = True

    @pytest.mark.asyncio
    async def test_authorize_post_rejects_invalid_csrf(self, oauth2_service):
        from fastapi import HTTPException
        from authglow.api.auth import authorize_post

        mock_request = MagicMock()
        mock_request.cookies = {}
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = MagicMock()
        mock_request.headers.get.return_value = ""

        csrf_service = MagicMock()
        csrf_service.validate_token = AsyncMock(return_value=False)

        storage = AsyncMock()
        mfa_service = MagicMock()
        session_service = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await authorize_post(
                request=mock_request,
                email="user@example.com",
                password="password",
                client_id="test-client",
                redirect_uri="https://example.com/cb",
                csrf_token="bad-token",
                storage=storage,
                oauth2_service=oauth2_service,
                mfa_service=mfa_service,
                session_service=session_service,
                csrf_service=csrf_service,
            )
        assert exc_info.value.status_code == 403
        assert "CSRF" in exc_info.value.detail


class TestCSRFOnMFAVerifyRoute:
    """Tests for CSRF protection on POST /oauth2/mfa-verify."""

    @pytest.mark.asyncio
    async def test_mfa_verify_rejects_invalid_csrf(self):
        from fastapi import HTTPException
        from authglow.api.auth import oauth2_mfa_verify

        mock_request = MagicMock()
        mock_request.cookies = {"csrf_session_id": "bad-session"}
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"
        mock_request.headers = MagicMock()
        mock_request.headers.get.return_value = ""

        csrf_service = MagicMock()
        csrf_service.validate_token = AsyncMock(return_value=False)

        storage = AsyncMock()
        oauth2_service = MagicMock()
        mfa_service = MagicMock()
        session_service = MagicMock()

        with pytest.raises(HTTPException) as exc_info:
            await oauth2_mfa_verify(
                request=mock_request,
                session_token="session-abc",
                code="123456",
                trust_device=False,
                csrf_token="wrong-token",
                storage=storage,
                oauth2_service=oauth2_service,
                mfa_service=mfa_service,
                session_service=session_service,
                csrf_service=csrf_service,
            )
        assert exc_info.value.status_code == 403
        assert "CSRF" in exc_info.value.detail


class TestCSRFOnConsentRoute:
    """Tests for CSRF protection on POST /oauth2/consent."""

    @pytest.fixture(autouse=True)
    def _disable_limiter(self):
        from authglow.core.rate_limit import limiter

        limiter.enabled = False
        yield
        limiter.enabled = True

    @pytest.mark.asyncio
    async def test_consent_rejects_invalid_csrf(self):
        from fastapi import HTTPException
        from authglow.api.oauth_consent_handler import process_consent

        mock_request = MagicMock()
        mock_request.cookies = {"csrf_session_id": "invalid-session"}
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        csrf_service = MagicMock()
        csrf_service.validate_token = AsyncMock(return_value=False)

        session_service = MagicMock()
        consent_service = MagicMock()
        oauth2_service = MagicMock()
        audit_service = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await process_consent(
                request=mock_request,
                session_token="session-abc",
                approved="true",
                remember="false",
                csrf_token="bad-token",
                session_service=session_service,
                consent_service=consent_service,
                oauth2_service=oauth2_service,
                audit_service=audit_service,
                csrf_service=csrf_service,
            )
        assert exc_info.value.status_code == 403
        assert "CSRF" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_consent_accepts_valid_csrf(self):
        from authglow.api.oauth_consent_handler import process_consent
        from authglow.models.token import AuthorizationCode

        mock_request = MagicMock()
        mock_request.cookies = {"csrf_session_id": "good-session"}
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        csrf_service = MagicMock()
        csrf_service.validate_token = AsyncMock(return_value=True)

        session_service = MagicMock()
        session_service.get_consent_session = AsyncMock(
            return_value={
                "session_token": "tok",
                "user_id": "user-1",
                "client_id": "client-1",
                "redirect_uri": "https://example.com/cb",
                "scope": "read",
                "state": None,
            }
        )
        session_service.delete_consent_session = AsyncMock()

        consent_service = MagicMock()
        oauth2_service = MagicMock()
        auth_code = AuthorizationCode(
            code="auth-code-xyz",
            client_id="client-1",
            user_id="user-1",
            redirect_uri="https://example.com/cb",
            scope="read",
            expires_at=datetime.now(),
        )
        oauth2_service.create_authorization_code = AsyncMock(return_value=auth_code)
        audit_service = AsyncMock()

        result = await process_consent(
            request=mock_request,
            session_token="tok",
            approved="true",
            remember="false",
            csrf_token="valid-token",
            session_service=session_service,
            consent_service=consent_service,
            oauth2_service=oauth2_service,
            audit_service=audit_service,
            csrf_service=csrf_service,
        )

        from fastapi.responses import RedirectResponse

        assert isinstance(result, RedirectResponse)
        assert "code=auth-code-xyz" in result.headers.get("location", "")


class TestCSRFTokenSecurity:
    """Security-specific tests for CSRF tokens."""

    def test_token_length_meets_remediation_spec(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            token = svc._new_token()

            decoded_len = len(token)
            assert decoded_len >= 32, (
                f"Token too short: {decoded_len} chars; spec says token_urlsafe(32)"
            )

    def test_token_generated_has_tags_and_signals(self, test_settings):
        from authglow.services.csrf import CSRFTokenService
        import re

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            tokens = [svc._new_token() for _ in range(20)]

            for t in tokens:
                assert not re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}", t), (
                    f"Token {t[:8]}... looks like a UUID4 prefix -- "
                    "must use token_urlsafe, not uuid4"
                )

    def test_token_not_empty_string(self, test_settings):
        from authglow.services.csrf import CSRFTokenService

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            svc = CSRFTokenService()
            for _ in range(10):
                t = svc._new_token()
                assert t.strip(), "Token must not be empty/whitespace"
                assert "\n" not in t, "Token must not contain newlines"
                assert "\0" not in t, "Token must not contain null bytes"
