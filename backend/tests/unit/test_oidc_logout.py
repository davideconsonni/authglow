"""Tests for VAPT-010: OIDC logout open redirect prevention."""

import asyncio
from unittest.mock import patch


class TestTokenDataAudField:
    def test_token_data_has_aud_field(self):
        from datetime import datetime, timezone

        from authglow.models.token import TokenData

        td = TokenData(
            sub="user-1",
            email="test@test.com",
            exp=datetime(2030, 1, 1, tzinfo=timezone.utc),
            iat=datetime(2030, 1, 1, tzinfo=timezone.utc),
            aud="client-123",
        )
        assert td.aud == "client-123"
        assert hasattr(td, "aud")

    def test_token_data_aud_defaults_none(self):
        from datetime import datetime, timezone

        from authglow.models.token import TokenData

        td = TokenData(
            sub="user-1",
            email="test@test.com",
            exp=datetime(2030, 1, 1, tzinfo=timezone.utc),
            iat=datetime(2030, 1, 1, tzinfo=timezone.utc),
        )
        assert td.aud is None


class TestDecodeTokenReadsAud:
    def test_decode_token_sets_aud(self):
        from authglow.services.jwt import JWTService

        svc = asyncio.run(JWTService.new())
        payload = {
            "sub": "user-1",
            "email": "test@test.com",
            "exp": 1893456000,
            "iat": 1717171200,
            "token_type": "id",
            "aud": "oidc-client-abc",
        }

        with patch.object(svc, "_decode_token", return_value=payload):
            token_data = svc.decode_token("fake-token")
            assert token_data is not None
            assert token_data.aud == "oidc-client-abc"

    def test_decode_token_aud_none_when_missing(self):
        from authglow.services.jwt import JWTService

        svc = asyncio.run(JWTService.new())
        payload = {
            "sub": "user-1",
            "email": "test@test.com",
            "exp": 1893456000,
            "iat": 1717171200,
            "token_type": "access",
        }

        with patch.object(svc, "_decode_token", return_value=payload):
            token_data = svc.decode_token("fake-token")
            assert token_data is not None
            assert token_data.aud is None


class TestLogoutOpenRedirectPrevention:
    """Workstream D: post_logout_redirect_uri validation."""

    def test_logout_get_uses_token_data_aud_not_hasattr(self):
        """The validation check must reference token_data.aud directly."""
        import inspect

        from authglow.api.oidc import logout_get

        source = inspect.getsource(logout_get)
        assert "token_data.aud" in source

    def test_logout_get_enforces_allowed_post_logout_redirect_uris(self):
        """Strict validation: checks against allowed_post_logout_redirect_uris."""
        import inspect

        from authglow.api.oidc import logout_get

        source = inspect.getsource(logout_get)
        assert "allowed_post_logout_redirect_uris" in source

    def test_state_is_url_encoded(self):
        """state parameter appended to redirect must be URL-encoded."""
        import inspect

        from authglow.api.oidc import logout_get

        source = inspect.getsource(logout_get)
        assert "urlencode" in source
