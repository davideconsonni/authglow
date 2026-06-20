"""OIDC amr/acr claims tests — Workstream F.

Validates that the ID token includes ``acr`` and ``amr`` claims based on
the authentication methods used to obtain the authorization code.

See ``docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`` for context
(OIDC Core §2, §5.5.1.1).
"""

import asyncio
from datetime import datetime, timezone

from authglow.models.token import AuthorizationCode

# ---------------------------------------------------------------------------
# ACR level computation
# ---------------------------------------------------------------------------


class TestComputeAcr:
    def test_empty_methods_returns_zero(self):
        from authglow.services.acr import ACR_LEVEL_ZERO, compute_acr

        assert compute_acr([]) == ACR_LEVEL_ZERO

    def test_password_only_returns_one(self):
        from authglow.services.acr import ACR_LEVEL_PASSWORD, AUTH_METHOD_PASSWORD, compute_acr

        assert compute_acr([AUTH_METHOD_PASSWORD]) == ACR_LEVEL_PASSWORD

    def test_password_plus_mfa_returns_two(self):
        from authglow.services.acr import (
            ACR_LEVEL_MFA,
            AUTH_METHOD_PASSWORD,
            AUTH_METHOD_TOTP,
            compute_acr,
        )

        assert compute_acr([AUTH_METHOD_PASSWORD, AUTH_METHOD_TOTP]) == ACR_LEVEL_MFA

    def test_webauthn_returns_three(self):
        from authglow.services.acr import ACR_LEVEL_PASSKEY, AUTH_METHOD_WEBAUTHN, compute_acr

        assert compute_acr([AUTH_METHOD_WEBAUTHN]) == ACR_LEVEL_PASSKEY


# ---------------------------------------------------------------------------
# AuthorizationCode model
# ---------------------------------------------------------------------------


class TestAuthorizationCodeAcrAmrFields:
    def test_defaults_are_none(self):
        code = AuthorizationCode(
            client_id="c",
            user_id="u",
            redirect_uri="https://e.com/cb",
            scope="read",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        assert code.acr is None
        assert code.amr is None

    def test_set_and_read(self):
        code = AuthorizationCode(
            client_id="c",
            user_id="u",
            redirect_uri="https://e.com/cb",
            scope="read",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            acr="2",
            amr=["pwd", "mfa"],
        )
        assert code.acr == "2"
        assert code.amr == ["pwd", "mfa"]


# ---------------------------------------------------------------------------
# create_id_token — acr / amr propagation
# ---------------------------------------------------------------------------


class TestCreateIdTokenAcrAmr:
    def test_id_token_includes_acr_amr_when_provided(self, test_settings):
        from authglow.services.jwt import JWTService

        jwt_svc = asyncio.run(JWTService.new())
        token = jwt_svc.create_id_token(
            user_id="user-1",
            client_id="client-abc",
            scopes=["openid", "email"],
            user_claims={"email": "u@e.com", "email_verified": True},
            acr="2",
            amr=["pwd", "mfa"],
        )

        import jwt

        payload = jwt.decode(
            token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False}
        )
        assert payload.get("acr") == "2"
        assert payload.get("amr") == ["pwd", "mfa"]

    def test_id_token_omits_acr_amr_when_none(self, test_settings):
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
        assert "acr" not in payload
        assert "amr" not in payload


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscoveryIncludesAcrAmr:
    def test_claims_supported_includes_acr_amr(self, test_settings):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.oidc import router

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        response = http_client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        body = response.json()
        assert "acr" in body["claims_supported"]
        assert "amr" in body["claims_supported"]
