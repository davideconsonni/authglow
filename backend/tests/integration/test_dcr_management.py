"""RFC 7592 DCR Management integration tests — Workstream K.

Validates that ``GET`` / ``PUT`` / ``DELETE`` on
``/oauth2/register/{client_id}`` work with client HTTP Basic
authentication.
"""

import base64
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app_and_storage():
    from authglow.api import oidc as oidc_module
    from authglow.api.oidc import router
    from authglow.models.oauth_client import OAuth2Client
    from authglow.services.password import hash_password

    plaintext_secret = "my-client-secret-123"
    hashed = hash_password(plaintext_secret)

    client = OAuth2Client(
        client_id="dcr-client-1",
        client_secret=hashed,
        client_name="DCR Test Client",
        redirect_uris=["https://example.com/callback"],
        grant_types=["authorization_code"],
        allowed_scopes=["read"],
        is_active=True,
    )

    storage = MagicMock()
    storage.get_client = AsyncMock(return_value=client)
    storage.update_client = AsyncMock()
    storage.delete_client = AsyncMock(return_value=True)

    audit_svc = AsyncMock()
    audit_svc.log_event = AsyncMock()

    app = FastAPI()
    app.include_router(router)

    return app, storage, audit_svc, oidc_module, plaintext_secret


def _auth_header(client_id: str, client_secret: str) -> dict:
    credentials = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {"Authorization": f"Basic {credentials}"}


class TestDcrManagement:
    """RFC 7592: GET / PUT / DELETE with client credentials."""

    def test_get_returns_client_config(self):
        app, storage, audit_svc, oidc_mod, secret = _build_app_and_storage()
        http_client = TestClient(app)

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=audit_svc),
        ):
            response = http_client.get(
                "/oauth2/register/dcr-client-1",
                headers=_auth_header("dcr-client-1", secret),
            )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["client_id"] == "dcr-client-1"
        assert body["client_name"] == "DCR Test Client"
        assert "client_secret" not in body

    def test_get_rejects_wrong_secret(self):
        app, storage, audit_svc, oidc_mod, secret = _build_app_and_storage()
        http_client = TestClient(app)

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=audit_svc),
        ):
            response = http_client.get(
                "/oauth2/register/dcr-client-1",
                headers=_auth_header("dcr-client-1", "wrong-secret"),
            )

        assert response.status_code == 401, response.text

    def test_get_rejects_wrong_client_id(self):
        app, storage, audit_svc, oidc_mod, secret = _build_app_and_storage()
        http_client = TestClient(app)

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=audit_svc),
        ):
            response = http_client.get(
                "/oauth2/register/dcr-client-1",
                headers=_auth_header("different-client", secret),
            )

        assert response.status_code == 401, response.text

    def test_put_updates_client(self):
        app, storage, audit_svc, oidc_mod, secret = _build_app_and_storage()
        http_client = TestClient(app)

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=audit_svc),
        ):
            response = http_client.put(
                "/oauth2/register/dcr-client-1",
                headers=_auth_header("dcr-client-1", secret),
                json={"client_name": "Updated Name"},
            )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["client_name"] == "Updated Name"
        storage.update_client.assert_awaited_once()

    def test_delete_removes_client(self):
        app, storage, audit_svc, oidc_mod, secret = _build_app_and_storage()
        http_client = TestClient(app)

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=audit_svc),
        ):
            response = http_client.delete(
                "/oauth2/register/dcr-client-1",
                headers=_auth_header("dcr-client-1", secret),
            )

        assert response.status_code == 204, response.text
        storage.delete_client.assert_awaited_once_with("dcr-client-1")
