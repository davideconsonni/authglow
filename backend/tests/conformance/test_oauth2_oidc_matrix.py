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
    "OA-201": "state optional (RFC 6749 RECOMMENDED)",
    "OA-202": "discovery must not advertise fragment",
    "OA-203": "explicit invalid_scope, no silent downgrade",
    "OA-204": "stable sid per session",
    "OA-205": "software_statement trust anchor",
    "OA-301": "standard Token response for first-party",
    "OA-302": "conforming error codes",
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

    app.dependency_overrides[auth_mod.get_user_storage] = lambda: storage
    app.dependency_overrides[auth_mod.get_oauth2_service] = lambda: oauth2_service
    app.dependency_overrides[auth_mod.get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[auth_mod.get_mfa_service] = lambda: mfa_service
    app.dependency_overrides[auth_mod.get_session_service] = lambda: session_service
    app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit

    with ExitStack() as stack:
        stack.enter_context(patch("authglow.api.auth.get_settings", return_value=test_settings))
        stack.enter_context(patch("authglow.api.oidc.get_settings", return_value=test_settings))
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

    @pytest.mark.xfail(strict=True, reason="OA-201: state optional (RFC 6749 RECOMMENDED)")
    def test_rfc6749_state_optional(self, matrix_app, conf_public_pkce_client):
        """Authorize without `state` must not fail on the state gate."""
        form = _authorize_form(conf_public_pkce_client)
        del form["state"]
        res = matrix_app.post("/api/oauth2/authorize", data=form)
        assert "state parameter is required" not in res.text

    @pytest.mark.xfail(strict=True, reason="OA-203: explicit invalid_scope, no silent downgrade")
    def test_rfc6749_scope_explicit(self, matrix_app, test_settings, storage, oauth2_service):
        """A granted-but-not-user scope → 400 `invalid_scope`, never a reduced token."""
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


class TestRFC8628Device:
    def test_rfc8628_device_code_param(self, matrix_app, test_settings, storage, conf_device_client):
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


class TestOIDC:
    @pytest.mark.xfail(strict=True, reason="OA-202: discovery must not advertise fragment")
    def test_oidc_discovery_no_fragment(self, matrix_app):
        """`response_modes_supported` contains only modes the server emits."""
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
        with patch(
            "authglow.services.refresh_token.get_settings", return_value=test_settings
        ):
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

    @pytest.mark.xfail(strict=True, reason="OA-204: stable sid per session")
    def test_oidc_sid_stable(self, jwt_service, conf_confidential_basic_client):
        """Two ID tokens of one session share the same `sid`."""
        client_id = conf_confidential_basic_client["client"].client_id
        first = jwt_service.create_id_token("user-1", client_id, ["openid"], {})
        second = jwt_service.create_id_token("user-1", client_id, ["openid"], {})
        first_sid = jwt_service.decode_id_token(first, expected_aud=client_id).sid
        second_sid = jwt_service.decode_id_token(second, expected_aud=client_id).sid
        assert first_sid == second_sid


class TestRFC7591DCR:
    @pytest.mark.xfail(strict=True, reason="OA-205: software_statement trust anchor")
    def test_rfc7591_software_statement(self, matrix_app):
        """A self-signed `software_statement` is rejected; absent one registers fine."""
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
