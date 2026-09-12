"""OAuth2/OIDC conformance matrix (OA-001).

One test per protocol claim, named ``test_<rfc>_<claim>``. Green tests pin
behavior that already conforms; known gaps are marked
``pytest.mark.xfail(strict=True)`` citing the plan item (``OA-xxx``) so a
future fix surfaces as XPASS.

Uses the OA-002 fixtures in ``conformance/conftest.py`` exclusively.
Wire-format claims go through the full app (``backend/main.py`` +
``TestClient``); model/service claims use REAL storage and services
(no mocks for protocol assertions).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

OA_GAP = {
    "OA-301": "standard Token response for first-party",
    "OA-302": "conforming error codes",
    "OA-303": "c_hash bound to the authorization code",
    "OA-305": "client_auth_method in audit on every grant",
}

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
PASSWORD = "MatrixP@ss123!"


@pytest.fixture
def matrix_app(test_settings, storage, jwt_service, oauth2_service, mfa_service, session_service):
    """Minimal app (auth + oidc routers) with REAL test-bound services.

    Mirrors ``test_mfa_login_e2e_repro._build_e2e_app``: ``dependency_overrides``
    inject the root fixtures, an ``ExitStack`` rebinds every ``get_settings``
    site the request path touches (api modules + device/password/audit/refresh
    services), direct constructions get prebuilt test-bound instances, and the
    audit sink is mocked. ``register_oauth2_error_handler`` maps ``OAuth2Error``
    to the RFC 6749 §5.2 envelope.
    """
    from contextlib import ExitStack

    from fastapi import FastAPI

    from authglow.api import auth as auth_mod
    from authglow.api import oauth2_advanced as adv_mod
    from authglow.api import oidc as oidc_mod
    from authglow.api.oauth_errors import register_oauth2_error_handler
    from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
    from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
    from authglow.repositories.file.token_blacklist import FileTokenBlacklistRepository
    from authglow.services.auth.token_blacklist import _reset_token_blacklist
    from authglow.services.claim_policy import ClaimPolicyService
    from authglow.services.oauth_client import OAuth2ClientStorage
    from authglow.services.oidc import OIDCService
    from authglow.services.refresh_token import RefreshTokenService

    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock()

    claim_policy = ClaimPolicyService(settings=test_settings)
    oidc_service = OIDCService()
    oidc_service.user_storage = storage
    refresh_svc = RefreshTokenService(repository=FileRefreshTokenRepository(settings=test_settings))
    refresh_svc.audit_service = mock_audit
    client_storage = OAuth2ClientStorage(
        repository=FileOAuth2ClientRepository(settings=test_settings),
        settings=test_settings,
    )
    # OA-102: the revocation blacklist is a process-global singleton — rebind
    # it to the per-test repository so logout revocations never touch prod
    # data and never leak between tests.
    _reset_token_blacklist()

    app = FastAPI()
    register_oauth2_error_handler(app)
    app.include_router(auth_mod.router)
    app.include_router(oidc_mod.router)
    # OA-104: revocation + introspection (RFC 7009 / RFC 7662) are part of
    # the protocol surface the matrix pins — mount the advanced router too.
    app.include_router(adv_mod.router)

    app.dependency_overrides[auth_mod.get_user_storage] = lambda: storage
    app.dependency_overrides[auth_mod.get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[auth_mod.get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[auth_mod.get_mfa_service] = lambda: mfa_service
    app.dependency_overrides[auth_mod.get_session_service] = lambda: session_service
    app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit
    # OA-104: the advanced router has its own factories — rebind them to
    # the same test-bound instances (never the process-global singletons).
    app.dependency_overrides[adv_mod.get_refresh_token_service] = lambda: refresh_svc
    app.dependency_overrides[adv_mod.get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[adv_mod.get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[adv_mod.get_audit_service] = lambda: mock_audit
    app.dependency_overrides[adv_mod.get_user_storage] = lambda: storage

    with ExitStack() as stack:
        stack.enter_context(patch("authglow.api.auth.get_settings", return_value=test_settings))
        stack.enter_context(patch("authglow.api.oidc.get_settings", return_value=test_settings))
        stack.enter_context(
            patch("authglow.api.oauth2_advanced.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.services.device_auth.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.services.password.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.services.audit.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.services.refresh_token.get_settings", return_value=test_settings)
        )
        stack.enter_context(
            patch("authglow.api.auth.ClaimPolicyService", return_value=claim_policy)
        )
        stack.enter_context(patch("authglow.api.oidc.OIDCService", return_value=oidc_service))
        stack.enter_context(
            patch("authglow.api.auth.RefreshTokenService", return_value=refresh_svc)
        )
        stack.enter_context(
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=client_storage)
        )
        # OA-204: `logout_get` builds `OAuth2Service()` / `UserService()`
        # directly (local imports, not Depends) — rebind the definition
        # sites to the test-bound instances so GET-logout resolves
        # clients/users from the per-test store, never prod data.
        stack.enter_context(
            patch("authglow.services.oauth2.OAuth2Service", return_value=oauth2_service)
        )
        stack.enter_context(patch("authglow.services.user.UserService", return_value=storage))
        stack.enter_context(patch("authglow.api.oidc.AuditService", return_value=mock_audit))
        stack.enter_context(patch("authglow.api.auth.AuditService", return_value=mock_audit))
        stack.enter_context(
            patch(
                "authglow.services.auth.token_blacklist.get_token_blacklist_repository",
                return_value=FileTokenBlacklistRepository(settings=test_settings),
            )
        )
        yield TestClient(app, follow_redirects=False)


def _make_user(test_settings, storage, scopes) -> object:
    """Persist a real user; returns ``(user, email)``."""
    from authglow.models.user import User
    from authglow.services.password import hash_password

    email = f"matrix-{secrets.token_hex(4)}@example.com"
    user = User(
        email=email,
        hashed_password=hash_password(PASSWORD),
        is_active=True,
        email_verified=True,
        scopes=list(scopes),
    )
    asyncio.run(storage.create_user(user))
    return user, email


def _pkce_pair() -> tuple:
    """Return ``(verifier, s256_challenge)``."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8").rstrip("=")
    return verifier, challenge


def _dpop_proof_for(*, private_key, htu: str, htm: str = "POST") -> str:
    """Mint a DPoP proof JWT (ES256, embedded JWK) for the given target."""
    import json
    import time

    import jwt
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import ec

    if private_key is None:
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    now = int(time.time())
    return jwt.encode(
        {"htm": htm, "htu": htu, "iat": now, "jti": f"dpop-{time.time_ns()}"},
        private_key,
        algorithm="ES256",
        headers={"alg": "ES256", "typ": "dpop+jwt", "jwk": public_jwk},
    )


def _cookie_htu(test_settings) -> str:
    """Absolute URL of the cookie refresh endpoint (DPoP ``htu``)."""
    return f"{test_settings.issuer.rstrip('/')}/api/auth/refresh"


def _cookie_headers(test_settings, token, dpop_proof=None) -> dict:
    """Per-request ``Cookie`` header (explicit — avoids TestClient jar quirks)."""
    headers = {"Cookie": f"{test_settings.auth_cookie_refresh_name}={token}"}
    if dpop_proof is not None:
        headers["DPoP"] = dpop_proof
    return headers


def _mint_code(
    oauth2_service, *, client_id, user_id, redirect_uri, scope, challenge=None
) -> object:
    """Create a real authorization code via the service (skips login/consent)."""
    verifier, computed = _pkce_pair()
    challenge = challenge if challenge is not None else computed
    code = asyncio.run(
        oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    )
    return code, verifier


def _make_refresh_token(test_settings, *, user_id, client_id, scopes) -> object:
    """Create a real refresh token via the service (test-bound repo)."""
    from unittest.mock import patch

    from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
    from authglow.services.refresh_token import RefreshTokenService

    with patch("authglow.services.refresh_token.get_settings", return_value=test_settings):
        svc = RefreshTokenService(repository=FileRefreshTokenRepository(settings=test_settings))
        return asyncio.run(
            svc.create_refresh_token(user_id=user_id, client_id=client_id, scopes=list(scopes))
        )


def _get_refresh_token(test_settings, plaintext) -> object:
    """Fetch a refresh token by plaintext (None when unknown)."""
    from unittest.mock import patch

    from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
    from authglow.services.refresh_token import RefreshTokenService

    with patch("authglow.services.refresh_token.get_settings", return_value=test_settings):
        svc = RefreshTokenService(repository=FileRefreshTokenRepository(settings=test_settings))
        return asyncio.run(svc.get_refresh_token(plaintext))


def _make_no_consent_client(test_settings) -> dict:
    """Bespoke confidential client with ``require_consent=False`` (for OA-201).

    Lets a credential login complete straight to an authorization code
    (no consent screen), so the stateless completion path is pinnable.
    """
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
        client_name="Conformance No Consent",
        redirect_uris=["https://example.com/cb"],
        allowed_scopes=["openid", "read"],
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        require_consent=False,
        token_endpoint_auth_method="client_secret_basic",
    )
    with patch("authglow.services.password.get_settings", return_value=test_settings):
        created = asyncio.run(storage.create_client(client, secret))
    return {"client": created, "secret": secret}


def _make_client_with_scopes(test_settings, allowed_scopes) -> dict:
    """Bespoke confidential client (broader scopes than the user, for OA-203)."""
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
        client_name="Conformance Scope Probe",
        redirect_uris=["https://example.com/cb"],
        allowed_scopes=list(allowed_scopes),
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        token_endpoint_auth_method="client_secret_basic",
    )
    with patch("authglow.services.password.get_settings", return_value=test_settings):
        created = asyncio.run(storage.create_client(client, secret))
    return {"client": created, "secret": secret}


def _authorize_form(bundle, **extra) -> dict:
    form = {
        "client_id": bundle["client"].client_id,
        "redirect_uri": "https://example.com/cb",
        "scope": "read",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "state": secrets.token_urlsafe(32),
    }
    form.update(extra)
    return form


class TestRFC7636PKCE:
    def test_rfc7636_s256_only_advertised(self, matrix_app):
        """Discovery advertises S256 only (PKCE is S256-obligatory)."""
        res = matrix_app.get("/.well-known/openid-configuration")
        assert res.status_code == 200, res.text
        assert res.json()["code_challenge_methods_supported"] == ["S256"]


class TestRFC6749AuthorizationCode:
    def test_rfc6749_implicit_rejected(self, matrix_app, conf_public_pkce_client):
        """`response_type=token` → 302 `unsupported_response_type` (no implicit)."""
        res = matrix_app.post(
            "/api/oauth2/authorize",
            data=_authorize_form(conf_public_pkce_client, response_type="token"),
        )
        assert res.status_code == 302, res.text
        loc = res.headers["location"]
        assert loc.startswith("https://example.com/cb")
        assert "error=unsupported_response_type" in loc

    def test_rfc6749_hybrid_rejected(self, matrix_app, conf_public_pkce_client):
        """`response_type=code token` → 302 `unsupported_response_type` (no hybrid)."""
        res = matrix_app.post(
            "/api/oauth2/authorize",
            data=_authorize_form(conf_public_pkce_client, response_type="code token"),
        )
        assert res.status_code == 302, res.text
        assert "error=unsupported_response_type" in res.headers["location"]

    def test_rfc6749_redirect_exact_match(self, test_settings, conf_confidential_basic_client):
        """Exact-match redirect accepted; mismatch and unknown client rejected."""
        from authglow.core.cache import _reset_cache_registry
        from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
        from authglow.services.oauth_client import OAuth2ClientStorage

        _reset_cache_registry()
        repo = FileOAuth2ClientRepository(settings=test_settings)
        storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
        client_id = conf_confidential_basic_client["client"].client_id
        assert asyncio.run(storage.verify_redirect_uri(client_id, "https://example.com/cb")) is True
        assert (
            asyncio.run(storage.verify_redirect_uri(client_id, "https://example.com/other"))
            is False
        )
        assert (
            asyncio.run(storage.verify_redirect_uri("no-such-client", "https://example.com/cb"))
            is False
        )

    def test_rfc6749_password_grant_rejected(self, matrix_app):
        """`grant_type=password` → 400 `unsupported_grant_type` (deliberate)."""
        res = matrix_app.post("/oauth2/token", data={"grant_type": "password"})
        assert res.status_code == 400, res.text
        assert res.json()["error"] == "unsupported_grant_type"

    def test_rfc6749_state_echoed_intact(self, matrix_app, conf_public_pkce_client):
        """A valid state is echoed byte-identical in the error redirect."""
        state = secrets.token_urlsafe(32)
        res = matrix_app.post(
            "/api/oauth2/authorize",
            data=_authorize_form(conf_public_pkce_client, response_type="token", state=state),
        )
        assert res.status_code == 302, res.text
        query = parse_qs(urlparse(res.headers["location"]).query)
        assert query["state"] == [state]

    def test_rfc6749_state_optional(self, matrix_app, conf_public_pkce_client):
        """OA-201: authorize without `state` must not fail on the state gate."""
        form = _authorize_form(conf_public_pkce_client)
        del form["state"]
        res = matrix_app.post("/api/oauth2/authorize", data=form)
        assert "state parameter is required" not in res.text

    def test_rfc6749_state_absent_completes(
        self, matrix_app, test_settings, storage, oauth2_service
    ):
        """OA-201: a stateless request with credentials completes (code, no state echo)."""
        bundle = _make_no_consent_client(test_settings)
        user, email = _make_user(test_settings, storage, ["openid", "read"])
        verifier, challenge = _pkce_pair()
        res = matrix_app.post(
            "/api/oauth2/authorize",
            data={
                "email": email,
                "password": PASSWORD,
                "client_id": bundle["client"].client_id,
                "redirect_uri": "https://example.com/cb",
                "scope": "openid read",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
        assert res.status_code == 200, res.text
        redirect_url = res.json()["redirect_url"]
        query = parse_qs(urlparse(redirect_url).query)
        assert "code" in query
        assert "state" not in query

    def test_rfc6749_state_weak_redirects_without_echo(self, matrix_app, conf_public_pkce_client):
        """OA-201: a present-but-weak state → 302 `invalid_request`, never echoed."""
        form = _authorize_form(conf_public_pkce_client, state="short")
        res = matrix_app.post("/api/oauth2/authorize", data=form)
        assert res.status_code == 302, res.text
        query = parse_qs(urlparse(res.headers["location"]).query)
        assert query.get("error") == ["invalid_request"]
        assert "state" not in query

    def test_rfc6749_state_tainted_never_echoed(self, matrix_app, conf_public_pkce_client):
        """OA-201: a tainted state (log-injection chars) is dropped, not reflected."""
        form = _authorize_form(conf_public_pkce_client, state="goodstate-good\nFAKE")
        res = matrix_app.post("/api/oauth2/authorize", data=form)
        assert res.status_code == 302, res.text
        location = res.headers["location"]
        assert "\n" not in location
        assert "FAKE" not in location
        assert "state" not in parse_qs(urlparse(location).query)

    def test_rfc6749_scope_explicit(self, matrix_app, test_settings, storage, oauth2_service):
        """OA-203: a granted-but-not-user scope → 400 `invalid_scope`, never a reduced token."""
        bundle = _make_client_with_scopes(test_settings, ["read", "write"])
        user, _email = _make_user(test_settings, storage, ["read"])
        code, verifier = _mint_code(
            oauth2_service,
            client_id=bundle["client"].client_id,
            user_id=user.id,
            redirect_uri="https://example.com/cb",
            scope="read write",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": verifier,
            },
        )
        assert res.status_code == 400, res.text
        assert res.json()["error"] == "invalid_scope"

    @pytest.mark.xfail(strict=True, reason="OA-302: conforming error codes")
    def test_rfc6749_error_codes(
        self, matrix_app, test_settings, storage, oauth2_service, conf_confidential_basic_client
    ):
        """Wrong verifier → 400 `invalid_grant`; code/client mismatch → 401 `invalid_client`."""
        bundle = conf_confidential_basic_client
        user, _email = _make_user(test_settings, storage, ["read"])
        code, _verifier = _mint_code(
            oauth2_service,
            client_id=bundle["client"].client_id,
            user_id=user.id,
            redirect_uri="https://example.com/cb",
            scope="read",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": "wrong-verifier",
            },
        )
        assert res.status_code == 400, res.text
        assert res.json()["error"] == "invalid_grant"

    @pytest.mark.xfail(strict=True, reason="OA-301: standard Token response for first-party")
    def test_rfc6749_token_response_standard(
        self, matrix_app, test_settings, storage, oauth2_service
    ):
        """First-party redeem returns a `Token` (access/refresh/id_token), not `{'ok': True}`."""
        from authglow.api.auth import _first_party_oauth_client
        from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
        from authglow.services.oauth_client import OAuth2ClientStorage

        repo = FileOAuth2ClientRepository(settings=test_settings)
        fp_storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
        with patch("authglow.services.password.get_settings", return_value=test_settings):
            asyncio.run(
                fp_storage.create_client(
                    _first_party_oauth_client(test_settings), "first-party-public-client"
                )
            )
        user, _email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        code, verifier = _mint_code(
            oauth2_service,
            client_id=test_settings.oauth2_client_id,
            user_id=user.id,
            redirect_uri=test_settings.oauth2_first_party_redirect_uri,
            scope="openid read offline_access",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": test_settings.oauth2_first_party_redirect_uri,
                "client_id": test_settings.oauth2_client_id,
                "code_verifier": verifier,
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body.get("access_token"), body

    @pytest.mark.xfail(strict=True, reason="OA-305: client_auth_method in audit on every grant")
    def test_rfc6749_client_auth_method_audited(
        self, matrix_app, test_settings, storage, oauth2_service, conf_confidential_basic_client
    ):
        """OA-305: every ACCESS_TOKEN_ISSUED carries `client_auth_method`."""
        from authglow.api import auth as auth_mod
        from authglow.models.audit_events import AuditEventType

        mock_audit = MagicMock()
        mock_audit.log_event = AsyncMock()
        matrix_app.app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit

        bundle = conf_confidential_basic_client
        user, _email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        code, verifier = _mint_code(
            oauth2_service,
            client_id=bundle["client"].client_id,
            user_id=user.id,
            redirect_uri="https://example.com/cb",
            scope="openid read offline_access",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": verifier,
            },
        )
        assert res.status_code == 200, res.text
        issued = [
            call
            for call in mock_audit.log_event.await_args_list
            if call.kwargs.get("event_type") == AuditEventType.ACCESS_TOKEN_ISSUED
        ]
        assert issued, "no ACCESS_TOKEN_ISSUED audit event logged"
        for call in issued:
            metadata = call.kwargs.get("metadata")
            assert metadata is not None
            assert "client_auth_method" in metadata.model_dump(), metadata


class TestRFC8628Device:
    def test_rfc8628_device_code_param(
        self, matrix_app, test_settings, storage, conf_device_client
    ):
        """OA-101: the canonical `device_code=` parameter redeems an approved authorization."""
        from authglow.services.device_auth import DeviceAuthorizationService

        bundle = conf_device_client
        user, _email = _make_user(test_settings, storage, ["read"])
        svc = DeviceAuthorizationService(settings=test_settings)
        auth = asyncio.run(
            svc.create_device_authorization(
                client_id=bundle["client"].client_id,
                scope="read",
                verification_uri="https://example.com/device",
            )
        )
        assert asyncio.run(svc.approve(auth.user_code, user.id)) is True
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": DEVICE_GRANT,
                "device_code": auth.device_code,
                "client_id": bundle["client"].client_id,
            },
        )
        assert res.status_code == 200, res.text
        assert res.json().get("access_token"), res.text

    def test_rfc8628_device_code_legacy_alias(
        self, matrix_app, test_settings, storage, conf_device_client
    ):
        """OA-101: the deprecated `code=` alias still redeems (with a warning)."""
        from authglow.services.device_auth import DeviceAuthorizationService

        bundle = conf_device_client
        user, _email = _make_user(test_settings, storage, ["read"])
        svc = DeviceAuthorizationService(settings=test_settings)
        auth = asyncio.run(
            svc.create_device_authorization(
                client_id=bundle["client"].client_id,
                scope="read",
                verification_uri="https://example.com/device",
            )
        )
        assert asyncio.run(svc.approve(auth.user_code, user.id)) is True
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": DEVICE_GRANT,
                "code": auth.device_code,
                "client_id": bundle["client"].client_id,
            },
        )
        assert res.status_code == 200, res.text
        assert res.json().get("access_token"), res.text

    def test_rfc8628_device_code_missing(self, matrix_app, conf_device_client):
        """OA-101: neither `device_code` nor `code` → `invalid_request`."""
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": DEVICE_GRANT,
                "client_id": conf_device_client["client"].client_id,
            },
        )
        assert res.status_code == 400, res.text
        assert res.json()["error"] == "invalid_request"


class TestOAuth2CookieFlow:
    def test_oauth2_cookie_flow_rejects_foreign_client(
        self, matrix_app, test_settings, storage, conf_confidential_basic_client
    ):
        """OA-103a: a cookie minted for another client → 401, never rotated.

        The cookie flow is explicitly first-party-only (option B binding
        with option A policy gates): foreign cookies are rejected even
        though the owner resolves fine.
        """
        bundle = conf_confidential_basic_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        rt = _make_refresh_token(
            test_settings,
            user_id=user.id,
            client_id=bundle["client"].client_id,
            scopes=["openid", "read"],
        )
        res = matrix_app.post("/api/auth/refresh", headers=_cookie_headers(test_settings, rt.token))
        assert res.status_code == 401, res.text
        assert "first-party" in res.text
        # The foreign token must not have been consumed by the attempt.
        rt_check = _get_refresh_token(test_settings, rt.token)
        assert rt_check is not None and not rt_check.used and not rt_check.revoked

    def test_oauth2_cookie_flow_requires_dpop_for_bound_client(
        self, matrix_app, test_settings, storage, conf_dpop_bound_client
    ):
        """OA-103b: a dpop-bound cookie without proof → 400 `missing_dpop_proof`.

        The cookie flow enforces the same DPoP gate as the standard
        refresh branch (RFC 9449 §5) — resolved on the owning client,
        not on the hardcoded first-party id.
        """
        bundle = conf_dpop_bound_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        rt = _make_refresh_token(
            test_settings,
            user_id=user.id,
            client_id=bundle["client"].client_id,
            scopes=["openid", "read"],
        )
        res = matrix_app.post("/api/auth/refresh", headers=_cookie_headers(test_settings, rt.token))
        assert res.status_code == 400, res.text
        assert res.json()["error"] == "invalid_request"
        assert res.json().get("error_code") == "missing_dpop_proof"
        rt_check = _get_refresh_token(test_settings, rt.token)
        assert rt_check is not None and not rt_check.used and not rt_check.revoked

    def test_oauth2_cookie_flow_rejects_verified_dpop_foreign(
        self, matrix_app, test_settings, storage, conf_dpop_bound_client
    ):
        """OA-103b: a *valid* proof for a foreign dpop cookie still → 401.

        The DPoP gate runs before the first-party check: verification
        succeeds, then the foreign session is rejected — and the token
        is not consumed.
        """
        bundle = conf_dpop_bound_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        rt = _make_refresh_token(
            test_settings,
            user_id=user.id,
            client_id=bundle["client"].client_id,
            scopes=["openid", "read"],
        )
        proof = _dpop_proof_for(private_key=None, htu=_cookie_htu(test_settings))
        res = matrix_app.post(
            "/api/auth/refresh",
            headers=_cookie_headers(test_settings, rt.token, dpop_proof=proof),
        )
        assert res.status_code == 401, res.text
        assert "first-party" in res.text
        rt_check = _get_refresh_token(test_settings, rt.token)
        assert rt_check is not None and not rt_check.used and not rt_check.revoked

    def test_oauth2_cookie_flow_rejects_invalid_dpop_proof(
        self, matrix_app, test_settings, storage, conf_dpop_bound_client
    ):
        """OA-103b: a proof for the wrong target → 401 with a DPoP `error_code`.

        Proves the cookie flow *verifies* the proof (htu-bound) instead
        of merely checking presence: a token-endpoint proof is rejected
        here with a DPoP error, not the first-party rejection.
        """
        bundle = conf_dpop_bound_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        rt = _make_refresh_token(
            test_settings,
            user_id=user.id,
            client_id=bundle["client"].client_id,
            scopes=["openid", "read"],
        )
        wrong_htu = f"{test_settings.issuer.rstrip('/')}/oauth2/token"
        proof = _dpop_proof_for(private_key=None, htu=wrong_htu)
        res = matrix_app.post(
            "/api/auth/refresh",
            headers=_cookie_headers(test_settings, rt.token, dpop_proof=proof),
        )
        assert res.status_code == 401, res.text
        assert res.json().get("error_code") is not None, res.text
        rt_check = _get_refresh_token(test_settings, rt.token)
        assert rt_check is not None and not rt_check.used and not rt_check.revoked

    def test_oauth2_cookie_flow_first_party_rotates(self, matrix_app, test_settings, storage):
        """OA-103: the dashboard flow still works — first-party cookie → 200 + rotation + audit.

        Regression guard for the OA-103 rewire: the first-party owner
        passes the grant gate, needs no DPoP proof (not bound), rotates,
        and logs the shared `ACCESS_TOKEN_REFRESHED` shape with family.
        """
        from authglow.api import auth as auth_mod
        from authglow.models.audit_events import AuditEventType

        mock_audit = MagicMock()
        mock_audit.log_event = AsyncMock()
        matrix_app.app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit

        user, _email = _make_user(test_settings, storage, ["openid", "read", "offline_access"])
        rt = _make_refresh_token(
            test_settings,
            user_id=user.id,
            client_id=test_settings.oauth2_client_id,
            scopes=["openid", "read", "offline_access"],
        )
        res = matrix_app.post("/api/auth/refresh", headers=_cookie_headers(test_settings, rt.token))
        assert res.status_code == 200, res.text
        assert res.json() == {"ok": True}
        # The presented token was consumed by rotation...
        rt_check = _get_refresh_token(test_settings, rt.token)
        assert rt_check is not None and rt_check.used
        # ...a fresh refresh cookie was issued...
        new_cookie = res.cookies.get(test_settings.auth_cookie_refresh_name)
        assert new_cookie and new_cookie != rt.token
        # ...and the rotation was audited in the shared shape.
        refreshed = [
            call
            for call in mock_audit.log_event.await_args_list
            if call.kwargs.get("event_type") == AuditEventType.ACCESS_TOKEN_REFRESHED
        ]
        assert refreshed, "no ACCESS_TOKEN_REFRESHED audit event logged"
        metadata = refreshed[0].kwargs["metadata"]
        assert metadata.client_id == test_settings.oauth2_client_id
        assert metadata.refresh_token_family_id == getattr(rt, "family_id", None)


class TestRFC7009Revocation:
    def test_rfc7009_revoke_access_token(
        self, matrix_app, test_settings, storage, jwt_service, conf_confidential_basic_client
    ):
        """OA-104: revoke access → userinfo 401 + introspect inactive; unknown → 200 {}.

        This is the acceptance test from the plan (revoke branch was
        unread during the assessment). It passes: the JWT branch in
        ``oauth2_advanced.revoke_token`` blacklists the jti with audience
        binding and answers non-oracle 200s.
        """
        bundle = conf_confidential_basic_client
        user, email = _make_user(test_settings, storage, ["openid", "read"])
        token = jwt_service.create_access_token(
            user.id, email, ["openid", "read"], audience=bundle["client"].client_id
        )
        headers = {"Authorization": f"Bearer {token}"}
        creds = {
            "client_id": bundle["client"].client_id,
            "client_secret": bundle["secret"],
        }
        assert matrix_app.get("/oauth2/userinfo", headers=headers).status_code == 200
        res = matrix_app.post(
            "/oauth2/revoke",
            data={"token": token, "token_type_hint": "access_token", **creds},
        )
        assert res.status_code == 200, res.text
        assert res.json() == {}
        assert matrix_app.get("/oauth2/userinfo", headers=headers).status_code == 401
        res = matrix_app.post(
            "/oauth2/introspect",
            data={"token": token, "token_type_hint": "access_token", **creds},
        )
        assert res.status_code == 200, res.text
        assert res.json()["active"] is False
        res = matrix_app.post("/oauth2/revoke", data={"token": "no-such-token", **creds})
        assert res.status_code == 200, res.text
        assert res.json() == {}


class TestOIDC:
    def test_oidc_discovery_no_fragment(self, matrix_app):
        """OA-202: `response_modes_supported` contains only modes the server emits."""
        res = matrix_app.get("/.well-known/openid-configuration")
        assert res.status_code == 200, res.text
        assert "fragment" not in res.json()["response_modes_supported"]

    def test_oidc_logout_revokes(
        self, matrix_app, test_settings, storage, jwt_service, conf_confidential_basic_client
    ):
        """OA-102: logout → userinfo 401, introspect inactive, refresh `invalid_grant`."""
        from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
        from authglow.services.refresh_token import RefreshTokenService

        bundle = conf_confidential_basic_client
        user, email = _make_user(test_settings, storage, ["openid", "read"])
        token = jwt_service.create_access_token(
            user.id, email, ["openid", "read"], audience=bundle["client"].client_id
        )
        with patch("authglow.services.refresh_token.get_settings", return_value=test_settings):
            refresh_svc = RefreshTokenService(
                repository=FileRefreshTokenRepository(settings=test_settings)
            )
            rt = asyncio.run(
                refresh_svc.create_refresh_token(
                    user_id=user.id,
                    client_id=bundle["client"].client_id,
                    scopes=["openid", "read"],
                )
            )
        headers = {"Authorization": f"Bearer {token}"}
        res = matrix_app.get("/oauth2/userinfo", headers=headers)
        assert res.status_code == 200, res.text
        res = matrix_app.post("/oauth2/logout", headers=headers)
        assert res.status_code == 200, res.text
        res = matrix_app.get("/oauth2/userinfo", headers=headers)
        assert res.status_code == 401, res.text
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": rt.token,
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
            },
        )
        assert res.status_code == 401, res.text
        assert res.json()["error"] == "invalid_grant"

    def test_oidc_sid_stable(self, jwt_service, conf_confidential_basic_client):
        """OA-204: two ID tokens of one session share the same `sid`."""
        client_id = conf_confidential_basic_client["client"].client_id
        first = jwt_service.create_id_token("user-1", client_id, ["openid"], {})
        second = jwt_service.create_id_token("user-1", client_id, ["openid"], {})
        first_sid = jwt_service.decode_id_token(first, expected_aud=client_id).sid
        second_sid = jwt_service.decode_id_token(second, expected_aud=client_id).sid
        assert first_sid == second_sid

    def test_oidc_sid_rotates_on_new_login(self, jwt_service, conf_confidential_basic_client):
        """OA-204: a new login (`auth_time`) gets a new `sid`; another client
        gets a pairwise-different `sid` (no cross-client correlation)."""
        from datetime import datetime, timedelta, timezone

        client_id = conf_confidential_basic_client["client"].client_id
        t1 = datetime.now(timezone.utc)
        t2 = t1 + timedelta(hours=1)

        def _sid(cid, at):
            token = jwt_service.create_id_token("user-1", cid, ["openid"], {}, auth_time=at)
            return jwt_service.decode_id_token(token, expected_aud=cid).sid

        assert _sid(client_id, t1) == _sid(client_id, t1)
        assert _sid(client_id, t2) != _sid(client_id, t1)
        assert _sid("other-client", t1) != _sid(client_id, t1)

    def test_oidc_logout_notifies_session_clients_only(
        self, matrix_app, test_settings, storage, jwt_service
    ):
        """OA-204: logout iframes go to the hint client + live-RT holders only.

        A third client with a `frontchannel_logout_uri` but no session for
        the user gets no iframe — and nobody receives another client's `sid`.
        """
        from authglow.models.oauth_client import OAuth2Client
        from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
        from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
        from authglow.services.oauth_client import OAuth2ClientStorage
        from authglow.services.refresh_token import RefreshTokenService

        def _make_logout_client(name, logout_uri, post_logout_uri):
            secret = secrets.token_urlsafe(32)
            from authglow.core.cache import _reset_cache_registry

            _reset_cache_registry()
            repo = FileOAuth2ClientRepository(settings=test_settings)
            client_storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
            client = OAuth2Client(
                client_secret="placeholder",
                client_name=name,
                redirect_uris=["https://example.com/cb"],
                allowed_scopes=["openid", "read"],
                grant_types=["authorization_code", "refresh_token"],
                is_confidential=True,
                require_pkce=True,
                require_consent=False,
                token_endpoint_auth_method="client_secret_basic",
                frontchannel_logout_uri=logout_uri,
                allowed_post_logout_redirect_uris=[post_logout_uri],
            )
            with patch("authglow.services.password.get_settings", return_value=test_settings):
                created = asyncio.run(client_storage.create_client(client, secret))
            return created

        client_a = _make_logout_client(
            "Logout Hint", "https://a.example.com/logout", "https://a.example.com/bye"
        )
        _make_logout_client(
            "Logout Stranger", "https://b.example.com/logout", "https://b.example.com/bye"
        )
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        with patch("authglow.services.refresh_token.get_settings", return_value=test_settings):
            refresh_svc = RefreshTokenService(
                repository=FileRefreshTokenRepository(settings=test_settings)
            )
            asyncio.run(
                refresh_svc.create_refresh_token(
                    user_id=user.id,
                    client_id=client_a.client_id,
                    scopes=["openid", "read"],
                )
            )
        id_token = jwt_service.create_id_token(user.id, client_a.client_id, ["openid"], {})
        hint_sid = jwt_service.decode_id_token(
            id_token, expected_aud=client_a.client_id
        ).sid
        res = matrix_app.get(
            "/oauth2/logout",
            params={
                "id_token_hint": id_token,
                "post_logout_redirect_uri": "https://a.example.com/bye",
            },
        )
        assert res.status_code == 200, res.text
        body = res.text
        assert "https://a.example.com/logout" in body
        assert "https://b.example.com/logout" not in body
        assert hint_sid in body

    def test_oidc_offline_access_gate(
        self, matrix_app, test_settings, storage, oauth2_service, conf_confidential_basic_client
    ):
        """OA-304: without `offline_access` the exchange is access-only.

        Green pin for the OIDC Core §11 gate. Docs + audit warning for
        the missing refresh remain OA-304 work.
        """
        bundle = conf_confidential_basic_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        code, verifier = _mint_code(
            oauth2_service,
            client_id=bundle["client"].client_id,
            user_id=user.id,
            redirect_uri="https://example.com/cb",
            scope="openid read",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": verifier,
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body.get("access_token"), body
        assert body.get("id_token"), body
        assert body.get("refresh_token") is None, body

    @pytest.mark.xfail(strict=True, reason="OA-303: c_hash bound to the authorization code")
    def test_oidc_c_hash_bound(
        self, matrix_app, test_settings, storage, oauth2_service, conf_confidential_basic_client
    ):
        """OA-303: the ID token from a code flow carries a verifiable `c_hash`."""
        import jwt as pyjwt

        bundle = conf_confidential_basic_client
        user, _email = _make_user(test_settings, storage, ["openid", "read"])
        code, verifier = _mint_code(
            oauth2_service,
            client_id=bundle["client"].client_id,
            user_id=user.id,
            redirect_uri="https://example.com/cb",
            scope="openid read",
        )
        res = matrix_app.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code.code,
                "redirect_uri": "https://example.com/cb",
                "client_id": bundle["client"].client_id,
                "client_secret": bundle["secret"],
                "code_verifier": verifier,
            },
        )
        assert res.status_code == 200, res.text
        id_token = res.json().get("id_token")
        assert id_token, res.text
        payload = pyjwt.decode(id_token, options={"verify_signature": False})
        digest = hashlib.sha256(code.code.encode()).digest()
        expected = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
        assert payload.get("c_hash") == expected, payload


class TestRFC7591DCR:
    def test_rfc7591_software_statement(self, matrix_app):
        """OA-205: a self-signed `software_statement` is rejected; absent one registers fine."""
        import jwt as pyjwt

        junk = pyjwt.encode(
            {"iss": "evil-anchor"}, "not-a-trusted-key-padded-to-32-bytes", algorithm="HS256"
        )
        res = matrix_app.post(
            "/oauth2/register",
            json={
                "redirect_uris": ["https://example.com/cb"],
                "client_name": "Conformance Evil",
                "software_statement": junk,
            },
        )
        assert res.status_code == 400, res.text
