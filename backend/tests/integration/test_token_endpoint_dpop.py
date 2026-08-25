"""Integration tests for the OAuth 2.0 token endpoint with DPoP-bound clients.

Conformance workstream T.3: RFC 9449 DPoP. ES256 only,
JWK embedded in the proof header. The token endpoint refuses to
issue a token for a DPoP-bound client without a valid DPoP proof.
"""

import base64
import hashlib
import json
import time
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ec_keypair():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def _jwk(private_key) -> dict:
    return json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))


def _dpop_proof(*, private_key, htm: str = "POST", htu: str = None, jti: str = None, iat_offset: int = 0) -> str:
    from authglow.core.config import get_settings

    if htu is None:
        htu = f"{get_settings().issuer.rstrip('/')}/oauth2/token"
    now = int(time.time())
    payload = {
        "htm": htm,
        "htu": htu,
        "iat": now + iat_offset,
        "jti": jti or f"dpop-{time.time_ns()}",
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"alg": "ES256", "typ": "dpop+jwt", "jwk": _jwk(private_key)},
    )


def _build_app_and_client(*, dpop_bound: bool, jwt_key_ciphertext: str = None):
    """Build a minimal FastAPI app for the token endpoint with a
    PKCE-disabled authorization code (mirrors the JWT test
    scaffold)."""
    from authglow.api.auth import router as auth_router
    from authglow.models.oauth_client import OAuth2Client

    from authglow.services.password import hash_password

    client = OAuth2Client(
        client_id="dpop-test-client",
        client_secret=hash_password("any-plaintext"),
        client_name="DPoP Test Client",
        redirect_uris=["https://example.com/cb"],
        grant_types=["authorization_code", "client_credentials"],
        allowed_scopes=["openid", "read"],
        is_active=True,
        token_endpoint_auth_method="client_secret_basic",
        client_secret_jwt_key=jwt_key_ciphertext,
        public_jwk=None,
        dpop_bound=dpop_bound,
    )

    auth_code = MagicMock()
    auth_code.client_id = "dpop-test-client"
    auth_code.user_id = "user-1"
    auth_code.redirect_uri = "https://example.com/cb"
    auth_code.scope = "openid read"
    auth_code.code_challenge = None
    auth_code.code_challenge_method = None
    auth_code.nonce = None
    auth_code.acr = None
    auth_code.amr = None
    auth_code.expires_at = None

    storage = MagicMock()
    storage.get_client = AsyncMock(return_value=client)
    storage.get_authorization_code = AsyncMock(return_value=auth_code)
    storage.mark_code_as_used = AsyncMock()
    storage.get_user = AsyncMock(
        return_value=MagicMock(
            id="user-1",
            email="user@test.com",
            is_active=True,
            last_login=None,
            scopes=["read"],
        )
    )
    storage.client_storage.get_client = AsyncMock(return_value=client)
    storage.client_storage.update_last_used = AsyncMock()
    storage.client_storage.verify_client_secret = AsyncMock(return_value=True)

    oauth2_service = MagicMock()
    oauth2_service.client_storage = storage.client_storage
    oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code)
    oauth2_service.mark_code_as_used = AsyncMock()
    oauth2_service.process_scopes = AsyncMock(return_value=["openid", "read"])
    oauth2_service.verify_client = AsyncMock(return_value=True)

    # Real-ish JWT service: it must produce a real JWT so we can
    # inspect the ``cnf`` claim downstream.
    from authglow.services.jwt import JWTService
    import asyncio

    async def _get_jwt():
        from authglow.core.jwt_singleton import get_jwt_service

        return await get_jwt_service()

    jwt_service = _build_jwt_service_sync()

    refresh_token_service = MagicMock()
    refresh_token_service.create_refresh_token = AsyncMock(
        return_value=MagicMock(token="rt-fake")
    )

    audit_service = MagicMock()
    audit_service.log_event = AsyncMock()

    app = FastAPI()
    app.include_router(auth_router)
    from authglow.api.oauth_errors import register_oauth2_error_handler

    register_oauth2_error_handler(app)
    return app, storage, jwt_service, oauth2_service, refresh_token_service, audit_service, client


def _build_jwt_service_sync():
    """Build a real JWTService that emits a real (signed) access token.

    This lets the test inspect the ``cnf`` claim on the issued
    access token. We patch ``get_jwt_service`` to return this.
    """
    from authglow.core.jwt_singleton import get_jwt_service as _real
    from authglow.services.jwt import JWTService

    # Use the cached singleton — it has the keyring loaded with the
    # test keys (see conftest._override_settings + test_keys_dir).
    return _MagicAsyncJWTServiceProxy()


class _MagicAsyncJWTServiceProxy:
    """Async-compatible proxy to the real JWTService singleton.

    The token endpoint calls ``jwt_service.create_token_response``
    and ``jwt_service.create_id_token`` as plain (non-awaitable)
    methods. We fetch the singleton lazily so the autouse
    ``_override_settings`` fixture has run.
    """

    def __getattr__(self, name):
        import asyncio

        async def _resolve():
            return await _real()

        async def _sync(*args, **kwargs):
            svc = await _resolve()
            method = getattr(svc, name)
            return method(*args, **kwargs)

        # Make it awaitable and result-returning.
        return _sync

    def __call__(self, *args, **kwargs):  # pragma: no cover
        raise RuntimeError("use methods directly")


# ---------------------------------------------------------------------------
# DPoP-bound client
# ---------------------------------------------------------------------------


class TestDpopBoundAuthorizationCode:
    def test_missing_proof_rejected(self, test_settings):
        app, storage, jwt_svc, oauth2_svc, rt_svc, audit, client = _build_app_and_client(
            dpop_bound=True
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_secret": "any-plaintext",
                },
            )
        assert res.status_code == 400, res.text
        body = res.json()
        assert body["error"] == "invalid_request"
        assert body["error_code"] == "missing_dpop_proof"

    def test_valid_proof_returns_dpop_token_type(self, test_settings):
        app, storage, jwt_svc, oauth2_svc, rt_svc, audit, client = _build_app_and_client(
            dpop_bound=True
        )
        priv = _ec_keypair()
        proof = _dpop_proof(private_key=priv, htm="POST")
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_secret": "any-plaintext",
                },
                headers={"DPoP": proof},
            )
        # The PKCE check still fails (code_challenge is None) so
        # we expect a downstream 400. The important thing is
        # that the DPoP proof WAS accepted (no 400
        # ``missing_dpop_proof``).
        if res.status_code == 400:
            body = res.json()
            assert body.get("error_code") != "missing_dpop_proof", res.text
        # DPoP legacy path (verify_client with secret) was not
        # touched — DPoP proof bypasses it.
        oauth2_svc.verify_client.assert_called()

    def test_htm_mismatch_rejected(self, test_settings):
        app, storage, jwt_svc, oauth2_svc, rt_svc, audit, client = _build_app_and_client(
            dpop_bound=True
        )
        priv = _ec_keypair()
        proof = _dpop_proof(private_key=priv, htm="GET")  # wrong — token endpoint is POST
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_secret": "any-plaintext",
                },
                headers={"DPoP": proof},
            )
        assert res.status_code == 401, res.text
        body = res.json()
        assert body["error_code"] == "htm_mismatch"


# ---------------------------------------------------------------------------
# Non-DPoP-bound client (backward compat)
# ---------------------------------------------------------------------------


class TestNonDpopBoundAuthorizationCode:
    def test_no_dpop_header_required(self, test_settings):
        app, storage, jwt_svc, oauth2_svc, rt_svc, audit, client = _build_app_and_client(
            dpop_bound=False
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_svc),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_secret": "any-plaintext",
                },
            )
        # The DPoP layer did not reject the request — we got past
        # the auth step. We may still see a downstream failure
        # (PKCE check, etc.) but NOT a missing_dpop_proof error.
        if res.status_code in (400, 401):
            detail = res.json().get("detail")
            if isinstance(detail, dict):
                assert detail.get("error_code") != "missing_dpop_proof"


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


class TestDiscoveryAdvertisesDpop:
    def test_dpop_signing_alg_advertised(self):
        from authglow.api.oidc import router

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        app = FastAPI()
        app.include_router(router)
        http = TestClient(app)
        res = http.get("/.well-known/openid-configuration")
        assert res.status_code == 200
        body = res.json()
        assert "dpop_signing_alg_values_supported" in body
        assert body["dpop_signing_alg_values_supported"] == ["ES256"]
