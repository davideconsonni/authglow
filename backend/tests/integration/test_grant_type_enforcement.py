"""Integration tests for CONFORMANCE A4: per-client grant-type
authorization on ``/oauth2/token``.

RFC 6749 §5.2 ``unauthorized_client`` — a registered client may only
exercise the grant types listed in its registration. These tests pin
the enforcement for every supported branch of the token endpoint.
"""

import base64
import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

GRANTS = ["authorization_code", "client_credentials", "refresh_token"]

_VERIFIER = "a" * 43
_CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(_VERIFIER.encode()).digest()).decode().rstrip("=")


def _request_data(grant: str) -> dict:
    """Well-formed request per grant so only the guard can reject."""
    data = {
        "grant_type": grant,
        "client_id": "c1",
        "client_secret": "unused-mock",
        "redirect_uri": "https://example.com/cb",
        "code": "auth-code-1",
        "code_verifier": _VERIFIER,
        "refresh_token": "rt",
    }
    if grant != "authorization_code":
        del data["code_verifier"]
    if grant == "urn:ietf:params:oauth:grant-type:device_code":
        raise ValueError(grant)
    return data


def _build_app(allowed: bool):
    """Bare app + auth router; ``verify_grant_type`` is mocked to *allowed*.

    All pre-guard steps (code lookup, client authentication) are stubbed
    to succeed so the grant guard is the only rejection point.
    """
    from authglow.api.auth import get_oauth2_service
    from authglow.api.auth import router as auth_router
    from authglow.api.oauth_errors import register_oauth2_error_handler

    public_client = MagicMock()
    public_client.is_confidential = False
    public_client.is_active = True
    public_client.dpop_bound = False

    auth_code = MagicMock()
    auth_code.client_id = "c1"
    auth_code.user_id = "user-1"
    auth_code.redirect_uri = "https://example.com/cb"
    auth_code.scope = "openid read"
    auth_code.code_challenge = _CHALLENGE
    auth_code.code_challenge_method = "S256"

    oauth2_service = MagicMock()
    oauth2_service.verify_grant_type = AsyncMock(return_value=allowed)
    oauth2_service.verify_client = AsyncMock(return_value=True)
    oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code)
    oauth2_service.mark_code_as_used = AsyncMock()
    oauth2_service.process_scopes = AsyncMock(return_value=["openid", "read"])
    oauth2_service.client_storage.get_client = AsyncMock(return_value=public_client)

    app = FastAPI()
    register_oauth2_error_handler(app)
    app.include_router(auth_router)
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_service
    return app


@pytest.mark.parametrize("grant", GRANTS)
def test_unregistered_grant_rejected_with_unauthorized_client(grant):
    app = _build_app(allowed=False)
    res = TestClient(app).post("/oauth2/token", data=_request_data(grant))

    assert res.status_code == 400, res.text
    body = res.json()
    assert body["error"] == "unauthorized_client"
    assert grant in body["error_description"]


@pytest.mark.parametrize("grant", GRANTS)
def test_registered_grant_passes_the_guard(grant):
    """When the grant IS allowed, the request must NOT fail with
    ``unauthorized_client`` — it may fail later on other validation,
    but never at the guard."""
    app = _build_app(allowed=True)
    rt_svc = MagicMock()
    rt_svc.validate_and_rotate = AsyncMock(return_value=(None, "invalid refresh token"))
    with patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc):
        res = TestClient(app).post("/oauth2/token", data=_request_data(grant))

    body = res.json()
    assert res.status_code != 400 or body.get("error") != "unauthorized_client", res.text


def test_refresh_grant_propagates_scope_request():
    """F4 / RFC 6749 §6: the optional form ``scope`` is forwarded to
    ``validate_and_rotate`` as ``requested_scopes``; when the field is
    omitted, ``requested_scopes`` is ``None`` (no narrowing)."""
    app = _build_app(allowed=True)
    rt_svc = MagicMock()
    rt_svc.validate_and_rotate = AsyncMock(return_value=(None, "invalid refresh token"))
    with patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc):
        # With an explicit scope request.
        data = _request_data("refresh_token")
        data["scope"] = "read"
        TestClient(app).post("/oauth2/token", data=data)
        rt_svc.validate_and_rotate.assert_awaited_once()
        kwargs = rt_svc.validate_and_rotate.await_args.kwargs
        assert kwargs["requested_scopes"] == ["read"]

        # Without the form field: no narrowing requested.
        rt_svc.validate_and_rotate.reset_mock()
        TestClient(app).post("/oauth2/token", data=_request_data("refresh_token"))
        rt_svc.validate_and_rotate.assert_awaited_once()
        kwargs = rt_svc.validate_and_rotate.await_args.kwargs
        assert kwargs["requested_scopes"] is None
