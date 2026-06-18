"""OIDC Discovery conformance tests — Workstream E.

Validates the conformance remediation plan's claim that
``/.well-known/openid-configuration`` only advertises response
types and grant types that the Authorization Server actually
implements, and that the Dynamic Client Registration endpoint
refuses the deprecated ``implicit`` grant.

See ``docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`` for context
(implicit grant removal, OAuth 2.0 Security BCP §2.1.2).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_test_app(oidc_router) -> FastAPI:
    """Build a minimal FastAPI app hosting only the OIDC router.

    A fresh app per call keeps tests isolated from each other
    (no shared ``dependency_overrides`` between cases).
    """
    app = FastAPI()
    app.include_router(oidc_router)
    return app


# ---------------------------------------------------------------------------
# Discovery document — only announce what is implemented
# ---------------------------------------------------------------------------


class TestOpenIDConfigurationDiscovery:
    """Conformance: discovery metadata must not advertise unsupported flows.

    AuthGlow implements the ``authorization_code`` flow with PKCE.
    The implicit grant is forbidden by the OAuth 2.0 Security BCP
    and has never been wired to any handler in this codebase.
    """

    def test_discovery_no_implicit_grant(self, test_settings):
        from authglow.api.oidc import router

        app = _build_test_app(router)
        client = TestClient(app)

        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200, response.text
        body = response.json()
        assert "implicit" not in body["grant_types_supported"], (
            "Discovery must not advertise the deprecated 'implicit' grant "
            "(OAuth 2.0 Security BCP §2.1.2)."
        )

    def test_discovery_response_types_code_only(self, test_settings):
        from authglow.api.oidc import router

        app = _build_test_app(router)
        client = TestClient(app)

        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["response_types_supported"] == ["code"], (
            f"Only 'code' is implemented, got: {body['response_types_supported']}"
        )

    def test_discovery_code_challenge_s256_only(self, test_settings):
        from authglow.api.oidc import router

        app = _build_test_app(router)
        client = TestClient(app)

        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["code_challenge_methods_supported"] == ["S256"], (
            "PKCE S256 is the only supported code_challenge_method."
        )

    def test_discovery_required_endpoints_present(self, test_settings):
        from authglow.api.oidc import router

        app = _build_test_app(router)
        client = TestClient(app)

        response = client.get("/.well-known/openid-configuration")

        assert response.status_code == 200, response.text
        body = response.json()

        # Authorization Server core endpoints per OIDC Core §3 / OAuth 2.0 §3.
        assert body["issuer"], "issuer must be set"
        assert body["authorization_endpoint"].endswith("/oauth2/authorize")
        assert body["token_endpoint"].endswith("/oauth2/token")
        assert body["userinfo_endpoint"].endswith("/oauth2/userinfo")
        assert body["jwks_uri"].endswith("/.well-known/jwks.json")
        # Optional but always advertised by AuthGlow:
        assert body["registration_endpoint"].endswith("/oauth2/register")
        assert body["revocation_endpoint"].endswith("/oauth2/revoke")
        assert body["introspection_endpoint"].endswith("/oauth2/introspect")
        assert body["end_session_endpoint"].endswith("/oauth2/logout")


# ---------------------------------------------------------------------------
# Dynamic Client Registration — reject the implicit grant
# ---------------------------------------------------------------------------


class TestDynamicClientRegistrationRejectsImplicit:
    """Conformance: DCR must refuse registration requests that include the
    deprecated ``implicit`` grant type, both at the Pydantic model level
    (clear message) and at the DCR endpoint (HTTP 400).
    """

    def _build_mock_storage(self) -> MagicMock:
        storage = MagicMock()
        storage.generate_client_secret.return_value = "fake-plaintext-secret"
        storage.create_client = AsyncMock()
        return storage

    def _build_mock_audit(self) -> MagicMock:
        audit = MagicMock()
        audit.log_event = AsyncMock()
        return audit

    def test_dcr_rejects_implicit_grant(self, test_settings):
        from authglow.api import oidc as oidc_module
        from authglow.api.oidc import router

        storage = self._build_mock_storage()
        audit = self._build_mock_audit()

        app = _build_test_app(router)
        client = TestClient(app)

        with (
            patch.object(oidc_module, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_module, "AuditService", return_value=audit),
        ):
            response = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_name": "Legacy Implicit Client",
                    "grant_types": ["implicit"],
                    "token_endpoint_auth_method": "none",
                },
            )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "implicit" in str(detail).lower() or "grant" in str(detail).lower(), (
            f"Expected rejection message referencing 'implicit' or 'grant', got: {detail!r}"
        )
        # Storage must NOT have been called — the validator rejects before persistence.
        storage.create_client.assert_not_called()

    def test_dcr_accepts_authorization_code_only(self, test_settings):
        from authglow.api import oidc as oidc_module
        from authglow.api.oidc import router

        storage = self._build_mock_storage()
        audit = self._build_mock_audit()

        app = _build_test_app(router)
        client = TestClient(app)

        with (
            patch.object(oidc_module, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_module, "AuditService", return_value=audit),
        ):
            response = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_name": "Modern AuthCode Client",
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            )

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["grant_types"] == ["authorization_code"]
        assert body["client_id"]
        assert body["client_secret"] == "fake-plaintext-secret"
        # The mock storage must have received exactly one create call.
        storage.create_client.assert_awaited_once()
