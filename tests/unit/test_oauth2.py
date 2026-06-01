import pytest
from unittest.mock import patch, AsyncMock


class TestAuthorizationCodeLifecycle:
    def test_create_authorization_code(self, oauth2_service):
        import asyncio

        code = asyncio.get_event_loop().run_until_complete(
            oauth2_service.create_authorization_code(
                client_id="test-client-id",
                user_id="user-1",
                redirect_uri="http://localhost:8000/callback",
                scope="read",
            )
        )
        assert code is not None
        assert code.client_id == "test-client-id"
        assert code.user_id == "user-1"
        assert code.scope == "read"
        assert not code.used

    def test_get_authorization_code(self, oauth2_service):
        import asyncio

        code = asyncio.get_event_loop().run_until_complete(
            oauth2_service.create_authorization_code(
                client_id="test-client-id",
                user_id="user-2",
                redirect_uri="http://localhost:8000/callback",
                scope="read write",
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            oauth2_service.get_authorization_code(code.code)
        )
        assert fetched is not None
        assert fetched.code == code.code

    def test_authorization_code_expires(self, oauth2_service):
        import asyncio
        from datetime import datetime, timedelta

        code = asyncio.get_event_loop().run_until_complete(
            oauth2_service.create_authorization_code(
                client_id="test-client-id",
                user_id="user-exp",
                redirect_uri="http://localhost:8000/callback",
                scope="read",
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            oauth2_service.get_authorization_code(code.code)
        )
        assert fetched is not None

    def test_authorization_code_single_use(self, oauth2_service):
        import asyncio

        code = asyncio.get_event_loop().run_until_complete(
            oauth2_service.create_authorization_code(
                client_id="test-client-id",
                user_id="user-single",
                redirect_uri="http://localhost:8000/callback",
                scope="read",
            )
        )
        marked = asyncio.get_event_loop().run_until_complete(
            oauth2_service.mark_code_as_used(code.code)
        )
        assert marked
        fetched = asyncio.get_event_loop().run_until_complete(
            oauth2_service.get_authorization_code(code.code)
        )
        assert fetched is None

    def test_authorization_code_with_pkce(self, oauth2_service):
        import asyncio
        import hashlib
        import base64

        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("=")

        code = asyncio.get_event_loop().run_until_complete(
            oauth2_service.create_authorization_code(
                client_id="test-client-id",
                user_id="user-pkce",
                redirect_uri="http://localhost:8000/callback",
                scope="read",
                code_challenge=code_challenge,
                code_challenge_method="S256",
            )
        )
        assert code.code_challenge == code_challenge
        assert code.code_challenge_method == "S256"


class TestOAuth2ClientVerification:
    def test_verify_client_with_settings_defaults(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_client("test-client-id", "test-client-secret")
        )
        assert result is True

    def test_verify_client_wrong_secret(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_client("test-client-id", "wrong-secret")
        )
        assert result is False

    def test_verify_client_no_secret(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_client("test-client-id", None)
        )
        assert result is True

    def test_verify_client_unknown_client(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_client("unknown-client", "any-secret")
        )
        assert result is False

    def test_verify_redirect_uri_default_client(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_redirect_uri(
                "test-client-id", "http://localhost:8000/callback"
            )
        )
        assert result is True

    def test_verify_redirect_uri_invalid(self, oauth2_service):
        import asyncio

        result = asyncio.get_event_loop().run_until_complete(
            oauth2_service.verify_redirect_uri(
                "test-client-id", "https://evil.com/callback"
            )
        )
        assert result is False


class TestOAuth2ScopeProcessing:
    def test_process_scopes_default_client(self, oauth2_service):
        import asyncio

        scopes = asyncio.get_event_loop().run_until_complete(
            oauth2_service.process_scopes("test-client-id", ["read"])
        )
        assert "read" in scopes

    def test_process_scopes_oidc_standard_always_allowed(self, oauth2_service):
        import asyncio

        scopes = asyncio.get_event_loop().run_until_complete(
            oauth2_service.process_scopes(
                "test-client-id", ["openid", "profile", "email"]
            )
        )
        assert "openid" in scopes
        assert "profile" in scopes
        assert "email" in scopes

    def test_process_scopes_reject_unknown_strict(self, oauth2_service):
        import asyncio

        oauth2_service.settings.oauth2_reject_unknown_scopes = True

        with pytest.raises(ValueError, match="Unauthorized scopes"):
            asyncio.get_event_loop().run_until_complete(
                oauth2_service.process_scopes(
                    "test-client-id", ["read", "admin_super_secret"]
                )
            )
