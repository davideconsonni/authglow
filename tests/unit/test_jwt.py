import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch


class TestJWTTokenCreation:
    def test_create_access_token_roundtrip(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="user-123", email="test@example.com", scopes=["read", "write"]
        )
        assert isinstance(token, str)
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "user-123"
        assert decoded.email == "test@example.com"
        assert "read" in decoded.scopes
        assert "write" in decoded.scopes
        assert decoded.token_type == "access"

    def test_create_refresh_token_roundtrip(self, jwt_service):
        token = jwt_service.create_refresh_token(
            user_id="user-456", email="refresh@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "user-456"
        assert decoded.token_type == "refresh"

    def test_create_mfa_session_token_roundtrip(self, jwt_service):
        token = jwt_service.create_mfa_session_token(
            user_id="user-789", email="mfa@example.com"
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "user-789"
        assert decoded.token_type == "mfa_session"
        assert decoded.scopes == []

    def test_access_token_has_exp(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="user-exp", email="exp@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.exp is not None
        assert decoded.exp > datetime.now(timezone.utc) - timedelta(minutes=1)

    def test_refresh_token_has_exp(self, jwt_service):
        token = jwt_service.create_refresh_token(
            user_id="user-exp", email="rexp@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.exp is not None

    def test_token_type_default_is_access(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u1", email="t@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token)
        assert decoded.token_type == "access"

    def test_decode_invalid_token_returns_none(self, jwt_service):
        result = jwt_service.decode_token("invalid.token.string")
        assert result is None

    def test_decode_empty_token_returns_none(self, jwt_service):
        result = jwt_service.decode_token("")
        assert result is None

    def test_create_access_token_custom_expiry(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-custom",
            email="custom@example.com",
            scopes=["read"],
            expires_delta=timedelta(hours=1),
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        delta = decoded.exp - datetime.now(timezone.utc)
        assert delta > timedelta(minutes=55)
        assert delta < timedelta(hours=2)

    def test_create_token_response(self, jwt_service):
        response = jwt_service.create_token_response(
            user_id="u-resp",
            email="resp@example.com",
            scopes=["read", "write"],
            include_refresh=True,
        )
        assert response.access_token is not None
        assert response.refresh_token is not None
        assert response.token_type == "bearer"
        assert "read" in response.scope

    def test_create_token_response_without_refresh(self, jwt_service):
        response = jwt_service.create_token_response(
            user_id="u-resp2",
            email="resp2@example.com",
            scopes=["read"],
            include_refresh=False,
        )
        assert response.access_token is not None
        assert response.refresh_token is None


class TestJWTExpiration:
    def test_expired_token_should_be_rejected(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-expired",
            email="expired@example.com",
            scopes=["read"],
            expires_delta=timedelta(seconds=-1),
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is None, "Expired tokens should be rejected during decode"

    def test_token_expires_in_the_future_is_valid(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-valid",
            email="valid@example.com",
            scopes=["read"],
            expires_delta=timedelta(minutes=5),
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None

    def test_access_token_default_expiry_time(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-def", email="def@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        delta = decoded.exp - datetime.now(timezone.utc)
        assert delta > timedelta(minutes=25)
        assert delta < timedelta(minutes=35)


class TestJWTIDToken:
    def test_create_id_token(self, jwt_service):
        import jwt as pyjwt
        from authglow.core.config import get_settings

        token = jwt_service.create_id_token(
            user_id="u-oidc",
            client_id="test-client",
            scopes=["openid", "profile", "email"],
            user_claims={"name": "Test User", "email": "test@example.com"},
            nonce="abc123",
        )
        assert isinstance(token, str)
        settings = get_settings()
        with open(settings.public_key_path, "rb") as f:
            pub_key = f.read()
        payload = pyjwt.decode(
            token,
            pub_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": False, "verify_aud": False},
        )
        assert payload["sub"] == "u-oidc"
        assert payload["aud"] == "test-client"
        assert payload.get("nonce") == "abc123"

    def test_id_token_timestamps_are_integers(self, jwt_service):
        import jwt as pyjwt
        from authglow.core.config import get_settings

        token = jwt_service.create_id_token(
            user_id="u-ts", client_id="ts-client", scopes=["openid"], user_claims={}
        )
        settings = get_settings()
        with open(settings.public_key_path, "rb") as f:
            pub_key = f.read()
        payload = pyjwt.decode(
            token,
            pub_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": False, "verify_aud": False},
        )
        assert isinstance(payload.get("exp"), int), (
            "ID token exp should be integer, not datetime"
        )
        assert isinstance(payload.get("iat"), int), (
            "ID token iat should be integer, not datetime"
        )

    def test_id_token_contains_iss_and_aud(self, jwt_service):
        import jwt as pyjwt
        from authglow.core.config import get_settings

        token = jwt_service.create_id_token(
            user_id="u-iss", client_id="iss-client", scopes=["openid"], user_claims={}
        )
        settings = get_settings()
        with open(settings.public_key_path, "rb") as f:
            pub_key = f.read()
        payload = pyjwt.decode(
            token,
            pub_key,
            algorithms=[settings.jwt_algorithm],
            options={"verify_exp": False, "verify_aud": False},
        )
        assert "iss" in payload
        assert payload["aud"] == "iss-client"
