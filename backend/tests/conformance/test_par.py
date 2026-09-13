"""PAR conformance (RFC 9126, OA-501) — HTTP round-trips against test routers.

Uses its own minimal app (auth + par + oidc routers) with test-bound
service overrides, mirroring ``test_oauth2_oidc_matrix.matrix_app``.
Isolation rules per AGENTS.md: ``test_settings``-backed repos,
``settings=`` passed explicitly, runtime secrets only.
"""

import asyncio
import base64
import hashlib
import secrets
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.oauth_errors import register_oauth2_error_handler

PASSWORD = "MatrixP@ss123!"
REQUEST_URI_PREFIX = "urn:ietf:params:oauth:request_uri:"


def _pkce_pair() -> tuple:
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).decode().rstrip("=")


@pytest.fixture
def par_app(test_settings, storage, jwt_service, oauth2_service, mfa_service, session_service):
    """Minimal app (auth + par + oidc) with REAL test-bound services."""
    from authglow.api import auth as auth_mod
    from authglow.api import oidc as oidc_mod
    from authglow.api import par as par_mod
    from authglow.repositories.file.par import FilePushedAuthorizationRequestRepository
    from authglow.services.claim_policy import ClaimPolicyService
    from authglow.services.par import PushedAuthorizationService

    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock()

    claim_policy = ClaimPolicyService(settings=test_settings)

    par_svc = PushedAuthorizationService(
        repository=FilePushedAuthorizationRequestRepository(settings=test_settings),
        settings=test_settings,
    )

    app = FastAPI()
    register_oauth2_error_handler(app)
    app.include_router(auth_mod.router)
    app.include_router(par_mod.router)
    app.include_router(oidc_mod.router)

    app.dependency_overrides[auth_mod.get_user_storage] = lambda: storage
    app.dependency_overrides[auth_mod.get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[auth_mod.get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[auth_mod.get_mfa_service] = lambda: mfa_service
    app.dependency_overrides[auth_mod.get_session_service] = lambda: session_service
    app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit
    app.dependency_overrides[auth_mod.get_par_service] = lambda: par_svc
    app.dependency_overrides[par_mod.get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[par_mod.get_par_service] = lambda: par_svc
    app.dependency_overrides[par_mod.get_audit_service] = lambda: mock_audit

    with ExitStack() as stack:
        stack.enter_context(patch("authglow.api.auth.get_settings", return_value=test_settings))
        stack.enter_context(patch("authglow.api.oidc.get_settings", return_value=test_settings))
        stack.enter_context(patch("authglow.api.par.get_settings", return_value=test_settings))
        stack.enter_context(
            patch("authglow.services.password.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.services.refresh_token.get_settings", return_value=test_settings)
        )
        stack.enter_context(patch("authglow.api.auth.ClaimPolicyService", return_value=claim_policy))
        stack.enter_context(patch("authglow.api.oidc.OAuth2ClientStorage", return_value=MagicMock()))
        yield TestClient(app, follow_redirects=False)


def _make_user(test_settings, storage, scopes) -> object:
    from authglow.models.user import User
    from authglow.services.password import hash_password

    email = f"par-{secrets.token_hex(4)}@example.com"
    user = User(
        email=email,
        hashed_password=hash_password(PASSWORD),
        is_active=True,
        email_verified=True,
        scopes=list(scopes),
    )
    asyncio.run(storage.create_user(user))
    return user, email


def _make_par_client(test_settings, allowed_scopes, require_par=False) -> dict:
    from authglow.core.cache import _reset_cache_registry
    from authglow.models.oauth_client import OAuth2Client
    from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
    from authglow.services.oauth_client import OAuth2ClientStorage

    secret = secrets.token_urlsafe(32)
    _reset_cache_registry()
    repo = FileOAuth2ClientRepository(settings=test_settings)
    storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
    client = OAuth2Client(
        client_secret="placeholder",
        client_name="PAR Probe",
        redirect_uris=["https://example.com/cb"],
        allowed_scopes=list(allowed_scopes),
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        require_consent=False,
        token_endpoint_auth_method="client_secret_basic",
        require_par=require_par,
    )
    with patch("authglow.services.password.get_settings", return_value=test_settings):
        created = asyncio.run(storage.create_client(client, secret))
    return {"client": created, "secret": secret}


def _push(par_app, bundle, form_extra=None) -> dict:
    """Push a request; returns the PAR response body."""
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    form = {
        "client_id": bundle["client"].client_id,
        "client_secret": bundle["secret"],
        "redirect_uri": "https://example.com/cb",
        "scope": "openid read offline_access",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    form.update(form_extra or {})
    res = par_app.post("/oauth2/par", data=form)
    assert res.status_code == 201, res.text
    body = res.json()
    body["verifier"] = verifier
    body["state"] = state
    body["nonce"] = nonce
    return body


class TestPARService:
    """Service-level: TTL, single-use, client binding (no HTTP)."""

    def _svc(self, test_settings):
        from authglow.repositories.file.par import FilePushedAuthorizationRequestRepository
        from authglow.services.par import PushedAuthorizationService

        return PushedAuthorizationService(
            repository=FilePushedAuthorizationRequestRepository(settings=test_settings),
            settings=test_settings,
        )

    def test_create_consume_roundtrip(self, test_settings):
        svc = self._svc(test_settings)
        req = asyncio.run(
            svc.create_request(
                client_id="c1",
                redirect_uri="https://example.com/cb",
                scope="openid read",
                state="s",
            )
        )
        assert req.request_uri.startswith(REQUEST_URI_PREFIX)
        delta = (req.expires_at - req.created_at).total_seconds()
        assert 89.0 < delta <= 90.0, delta
        got = asyncio.run(svc.consume_request("c1", req.request_uri))
        assert got is not None and got.state == "s"
        assert asyncio.run(svc.consume_request("c1", req.request_uri)) is None

    def test_wrong_client_rejected(self, test_settings):
        svc = self._svc(test_settings)
        req = asyncio.run(
            svc.create_request(client_id="c1", redirect_uri="https://example.com/cb", scope="read")
        )
        assert asyncio.run(svc.consume_request("c2", req.request_uri)) is None

    def test_malformed_uri_rejected(self, test_settings):
        svc = self._svc(test_settings)
        assert asyncio.run(svc.consume_request("c1", "not-a-urn")) is None
        assert asyncio.run(svc.consume_request("c1", REQUEST_URI_PREFIX)) is None

    def test_expired_rejected(self, test_settings):
        from datetime import timedelta

        from authglow.core.datetime import utcnow
        from authglow.models.par import PushedAuthorizationRequest
        from authglow.repositories.file.par import FilePushedAuthorizationRequestRepository

        repo = FilePushedAuthorizationRequestRepository(settings=test_settings)
        req = PushedAuthorizationRequest(
            client_id="c1",
            redirect_uri="https://example.com/cb",
            scope="read",
            expires_at=utcnow() - timedelta(seconds=1),
        )
        asyncio.run(repo.create(req))
        assert asyncio.run(self._svc(test_settings).consume_request("c1", req.request_uri)) is None


class TestPARFlow:
    """HTTP: push → authorize with request_uri → code → tokens."""

    def test_roundtrip_uses_stored_params(
        self, par_app, test_settings, storage, oauth2_service
    ):
        """OA-501: stored params win — the echoed state is the pushed one."""
        bundle = _make_par_client(test_settings, ["openid", "read", "offline_access"])
        user, email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        pushed = _push(par_app, bundle)
        res = par_app.post(
            "/api/oauth2/authorize",
            data={
                "client_id": bundle["client"].client_id,
                "redirect_uri": "https://example.com/cb",
                "request_uri": pushed["request_uri"],
                "email": email,
                "password": PASSWORD,
            },
        )
        assert res.status_code == 200, res.text
        params = parse_qs(urlparse(res.json()["redirect_url"]).query)
        assert params.get("state") == [pushed["state"]], params
        tok = par_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": params["code"][0],
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": pushed["verifier"],
            },
        )
        assert tok.status_code == 200, tok.text
        assert tok.json().get("access_token"), tok.text

    def test_reuse_rejected(self, par_app, test_settings, storage):
        """OA-501: single-use — second presentation → 302 invalid_request."""
        bundle = _make_par_client(test_settings, ["openid", "read", "offline_access"])
        user, email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        pushed = _push(par_app, bundle)
        form = {
            "client_id": bundle["client"].client_id,
            "redirect_uri": "https://example.com/cb",
            "request_uri": pushed["request_uri"],
            "email": email,
            "password": PASSWORD,
        }
        first = par_app.post("/api/oauth2/authorize", data=form)
        assert first.status_code == 200, first.text
        second = par_app.post("/api/oauth2/authorize", data=form)
        assert second.status_code == 302, second.text
        assert "invalid_request" in second.headers["location"], second.headers["location"]

    def test_unknown_request_uri_rejected(self, par_app, test_settings, storage):
        """OA-501: garbage URN → 302 invalid_request, never 500/200."""
        bundle = _make_par_client(test_settings, ["openid", "read", "offline_access"])
        user, email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        res = par_app.post(
            "/api/oauth2/authorize",
            data={
                "client_id": bundle["client"].client_id,
                "redirect_uri": "https://example.com/cb",
                "request_uri": REQUEST_URI_PREFIX + secrets.token_urlsafe(32),
                "email": email,
                "password": PASSWORD,
            },
        )
        assert res.status_code == 302, res.text
        assert "invalid_request" in res.headers["location"], res.headers["location"]

    def test_require_par_client_rejects_plain_authorize(
        self, par_app, test_settings, storage
    ):
        """OA-501: FAPI-marked client without request_uri → 302 invalid_request."""
        bundle = _make_par_client(test_settings, ["openid", "read"], require_par=True)
        user, email = _make_user(test_settings, storage, ["openid", "read"])
        _verifier, challenge = _pkce_pair()
        res = par_app.post(
            "/api/oauth2/authorize",
            data={
                "client_id": bundle["client"].client_id,
                "redirect_uri": "https://example.com/cb",
                "scope": "openid read",
                "state": secrets.token_urlsafe(32),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "email": email,
                "password": PASSWORD,
            },
        )
        assert res.status_code == 302, res.text
        assert "invalid_request" in res.headers["location"], res.headers["location"]

    def test_discovery_advertises_par_endpoint(self, par_app):
        """OA-501: discovery announces the PAR endpoint."""
        res = par_app.get("/.well-known/openid-configuration")
        assert res.status_code == 200, res.text
        assert res.json()["pushed_authorization_request_endpoint"].endswith("/oauth2/par")


class TestOA502JarNotSupported:
    """OA-502: JAR ``request=`` / ``form_post`` explicitly rejected, never ignored."""

    def _classic_form(self, bundle, email, challenge, extra=None) -> dict:
        form = {
            "client_id": bundle["client"].client_id,
            "redirect_uri": "https://example.com/cb",
            "response_type": "code",
            "scope": "openid read offline_access",
            "state": secrets.token_urlsafe(32),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "email": email,
            "password": PASSWORD,
        }
        form.update(extra or {})
        return form

    def test_request_object_rejected(self, par_app, test_settings, storage):
        """OA-502: ``request=`` → 302 invalid_request (not silently ignored)."""
        bundle = _make_par_client(test_settings, ["openid", "read", "offline_access"])
        _user, email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        _verifier, challenge = _pkce_pair()
        res = par_app.post(
            "/api/oauth2/authorize",
            data=self._classic_form(
                bundle,
                email,
                challenge,
                {"request": "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.c2ln"},
            ),
        )
        assert res.status_code == 302, res.text
        assert "invalid_request" in res.headers["location"], res.headers["location"]

    def test_form_post_rejected_query_explicit_passes(self, par_app, test_settings, storage):
        """OA-502: ``form_post`` → 302; explicit ``query`` still completes."""
        bundle = _make_par_client(test_settings, ["openid", "read", "offline_access"])
        _user, email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        _verifier, challenge = _pkce_pair()
        rejected = par_app.post(
            "/api/oauth2/authorize",
            data=self._classic_form(bundle, email, challenge, {"response_mode": "form_post"}),
        )
        assert rejected.status_code == 302, rejected.text
        assert "invalid_request" in rejected.headers["location"], rejected.headers["location"]

        ok = par_app.post(
            "/api/oauth2/authorize",
            data=self._classic_form(bundle, email, challenge, {"response_mode": "query"}),
        )
        assert ok.status_code == 200, ok.text
        params = parse_qs(urlparse(ok.json()["redirect_url"]).query)
        assert "code" in params, params

    def test_discovery_pins_no_jar_no_form_post(self, par_app):
        """OA-502: discovery keeps JAR off and ``query``-only modes (OA-202 guard)."""
        res = par_app.get("/.well-known/openid-configuration")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["request_parameter_supported"] is False
        assert body["request_uri_parameter_supported"] is False
        assert body["response_modes_supported"] == ["query"]
        assert body["pushed_authorization_request_endpoint"].endswith("/oauth2/par")
