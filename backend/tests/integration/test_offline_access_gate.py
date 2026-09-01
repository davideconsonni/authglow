"""Integration tests for the OIDC Core §11 ``offline_access`` gate.

Refresh tokens on the ``authorization_code`` grant are issued only
when the granted scopes include ``offline_access``; clients without
it receive an access-token-only response (no error). The device_code
branch is covered in ``test_device_flow.py``.
"""

import base64
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.token import Token

_VERIFIER = "a" * 43
_CHALLENGE = (
    base64.urlsafe_b64encode(hashlib.sha256(_VERIFIER.encode()).digest()).decode().rstrip("=")
)


def _build_code_app(code_scope: str):
    """App with the token endpoint; the ``authorization_code`` happy
    path is stubbed up to the refresh-token issuance point. The granted
    scopes are what ``auth_code.scope`` carries (``process_scopes`` is
    a passthrough mock)."""
    from authglow.api.auth import (
        get_jwt_service,
        get_oauth2_service,
        get_user_storage,
    )
    from authglow.api.auth import router as auth_router
    from authglow.api.oauth_errors import register_oauth2_error_handler

    client = MagicMock()
    client.is_confidential = False
    client.is_active = True
    client.dpop_bound = False

    auth_code = MagicMock()
    auth_code.client_id = "c1"
    auth_code.user_id = "user-1"
    auth_code.redirect_uri = "https://example.com/cb"
    auth_code.scope = code_scope
    auth_code.code_challenge = _CHALLENGE
    auth_code.code_challenge_method = "S256"

    user = MagicMock(id="user-1", email="u@x.com", is_active=True)

    oauth2_service = MagicMock()
    oauth2_service.verify_grant_type = AsyncMock(return_value=True)
    oauth2_service.verify_client = AsyncMock(return_value=True)
    oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code)
    oauth2_service.mark_code_as_used = AsyncMock()
    oauth2_service.process_scopes = AsyncMock(
        side_effect=lambda cid, scopes: list(scopes)
    )
    oauth2_service.client_storage.get_client = AsyncMock(return_value=client)

    storage = MagicMock()
    storage.get_user = AsyncMock(return_value=user)

    jwt_svc = MagicMock()
    jwt_svc.create_token_response = MagicMock(
        return_value=Token(access_token="at-fake", token_type="Bearer", expires_in=300)
    )

    app = FastAPI()
    register_oauth2_error_handler(app)
    app.include_router(auth_router)
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[get_user_storage] = lambda: storage
    app.dependency_overrides[get_jwt_service] = lambda: jwt_svc
    return app


def _code_request() -> dict:
    return {
        "grant_type": "authorization_code",
        "client_id": "c1",
        "client_secret": "unused-mock",
        "redirect_uri": "https://example.com/cb",
        "code": "auth-code-1",
        "code_verifier": _VERIFIER,
    }


def _post_token(app, *, with_refresh_svc=True):
    rt_svc = MagicMock()
    rt_svc.create_refresh_token = AsyncMock(return_value=MagicMock(token="rt-opaque"))

    claim_policy = MagicMock()
    claim_policy.build_claims = AsyncMock(return_value={})

    with (
        patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc),
        patch("authglow.api.auth.ClaimPolicyService", return_value=claim_policy),
    ):
        res = TestClient(app).post("/oauth2/token", data=_code_request())

    return res, rt_svc


class TestOfflineAccessGateAuthorizationCode:
    """OIDC Core §11: refresh tokens are gated on ``offline_access``."""

    def test_offline_access_granted_issues_refresh_token(self):
        app = _build_code_app(code_scope="read offline_access")

        res, rt_svc = _post_token(app)

        assert res.status_code == 200, res.text
        body = res.json()
        assert body["access_token"] == "at-fake"
        assert body["refresh_token"] == "rt-opaque"
        rt_svc.create_refresh_token.assert_awaited_once()

    def test_without_offline_access_access_token_only(self):
        app = _build_code_app(code_scope="read")

        res, rt_svc = _post_token(app)

        assert res.status_code == 200, res.text
        body = res.json()
        assert body["access_token"] == "at-fake"
        # No refresh token issued — and no error, per OIDC §11.
        assert body["refresh_token"] is None
        rt_svc.create_refresh_token.assert_not_awaited()
