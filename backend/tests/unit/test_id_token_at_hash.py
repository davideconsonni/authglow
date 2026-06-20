"""OIDC at_hash / c_hash claims tests — Workstream M.

Validates that ``create_id_token`` computes ``at_hash`` when an access
token is provided and ``c_hash`` when an authorization code is provided
(OIDC Core §3.1.3.6).
"""

import asyncio
import base64
import hashlib


class TestAccessTokenHash:
    """M.1: at_hash claim in ID token when access_token is provided."""

    def test_at_hash_present_when_access_token_provided(self, test_settings):
        from authglow.services.jwt import JWTService

        access_token = "my-access-token-abc123"
        jwt_svc = asyncio.run(JWTService.new())
        token = jwt_svc.create_id_token(
            user_id="user-1",
            client_id="client-abc",
            scopes=["openid", "email"],
            user_claims={"email": "u@e.com", "email_verified": True},
            access_token=access_token,
        )

        import jwt

        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
        )
        assert "at_hash" in payload

        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode()).digest()[:16])
            .rstrip(b"=")
            .decode()
        )
        assert payload["at_hash"] == expected

    def test_at_hash_absent_when_no_access_token(self, test_settings):
        from authglow.services.jwt import JWTService

        jwt_svc = asyncio.run(JWTService.new())
        token = jwt_svc.create_id_token(
            user_id="user-1",
            client_id="client-abc",
            scopes=["openid", "email"],
            user_claims={"email": "u@e.com", "email_verified": True},
        )

        import jwt

        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
        )
        assert "at_hash" not in payload


class TestCodeHash:
    """M.2: c_hash claim in ID token when authorization_code is provided."""

    def test_c_hash_present_when_code_provided(self, test_settings):
        from authglow.services.jwt import JWTService

        code = "auth-code-value-xyz"
        jwt_svc = asyncio.run(JWTService.new())
        token = jwt_svc.create_id_token(
            user_id="user-1",
            client_id="client-abc",
            scopes=["openid"],
            user_claims={"email": "u@e.com", "email_verified": True},
            authorization_code=code,
        )

        import jwt

        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
        )
        assert "c_hash" in payload

        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(code.encode()).digest()[:16])
            .rstrip(b"=")
            .decode()
        )
        assert payload["c_hash"] == expected

    def test_c_hash_absent_when_no_code(self, test_settings):
        from authglow.services.jwt import JWTService

        jwt_svc = asyncio.run(JWTService.new())
        token = jwt_svc.create_id_token(
            user_id="user-1",
            client_id="client-abc",
            scopes=["openid"],
            user_claims={"email": "u@e.com", "email_verified": True},
        )

        import jwt

        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
        )
        assert "c_hash" not in payload
