"""API tests for the admin Webhook Endpoints CRUD (initiative B, B1).

Exercises the real ``FileWebhookRepository`` against per-test tmp storage
(same integration-style pattern as the claim-policy API tests).
Admin routes gate on RBAC permissions (``require_permission`` decodes the
bearer token itself), so an autouse fixture fakes the token decode and
grants ``clients.manage`` + ``admin.read`` for the test caller, and the
client sends a dummy Bearer token on every request.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.auth import get_current_user
from authglow.api.webhooks import get_webhook_repository, router
from authglow.models.token import TokenData
from authglow.models.user import User
from authglow.repositories.file.webhook import FileWebhookRepository
from authglow.services.rbac import RBACService

ADMIN = User(
    id="admin-1",
    email="admin@example.com",
    hashed_password="not-a-real-hash",
    is_active=True,
    email_verified=True,
    scopes=["read", "write"],
)


@pytest.fixture(autouse=True)
def _mock_rbac_admin():
    token_data = TokenData(
        sub="admin-1",
        email="admin@example.com",
        scopes=["read", "write"],
        token_type="access",
        exp=datetime.now(timezone.utc) + timedelta(hours=1),
        iat=datetime.now(timezone.utc),
        # OA-504: PermissionChecker requires aud presence.
        aud="authglow-internal",
    )
    fake_svc = MagicMock()
    fake_svc.decode_token = MagicMock(return_value=token_data)
    with (
        patch("authglow.core.permissions.get_jwt_service", new_callable=AsyncMock) as mock_jwt,
        patch.object(RBACService, "get_user_permissions", new_callable=AsyncMock) as mock_perms,
    ):
        mock_jwt.return_value = fake_svc
        mock_perms.return_value = {"clients.manage", "admin.read"}
        yield


def _build(test_settings):
    app = FastAPI()
    app.include_router(router)
    # The endpoints take the full User via get_current_user (audit
    # fields); the permission gate goes through PermissionChecker
    # (covered by the _mock_rbac_admin fixture).
    app.dependency_overrides[get_current_user] = lambda: ADMIN
    app.dependency_overrides[get_webhook_repository] = lambda: FileWebhookRepository(
        settings=test_settings
    )
    return TestClient(app, headers={"Authorization": "Bearer test-token"})


DEFAULT_EVENTS = ["user.created"]


def _create(client, url="https://example.com/hook", events=None, insecure=None):
    body = {
        "url": url,
        # ``None`` → default catalog entry; an explicit ``[]`` is passed
        # through so the rejection path can be tested.
        "events": DEFAULT_EVENTS if events is None else events,
    }
    if insecure is not None:
        body["insecure"] = insecure
    return client.post("/api/admin/webhooks", json=body)


class TestCreateWebhook:
    def test_create_returns_secret_once_and_masks_reads(self, test_settings):
        client = _build(test_settings)

        resp = _create(client)
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["id"].startswith("wh_")
        assert body["secret"].startswith("whsec_")
        assert body["masked_secret"].startswith("whsec_") and "…" in body["masked_secret"]

        # Reads never reveal the plaintext secret.
        listed = client.get("/api/admin/webhooks").json()
        assert len(listed) == 1
        assert "secret" not in listed[0]
        assert listed[0]["masked_secret"] == body["masked_secret"]
        detail = client.get(f"/api/admin/webhooks/{body['id']}").json()
        assert "secret" not in detail

    def test_create_rejects_unknown_event_type(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, events=["user.createdd"])
        assert resp.status_code == 400
        assert "Unknown event types" in resp.json()["detail"]

    def test_create_rejects_empty_events(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, events=[])
        assert resp.status_code == 400
        assert "At least one event type" in resp.json()["detail"]

    def test_create_deduplicates_events(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, events=["user.created", "user.created"])
        assert resp.status_code == 201
        assert resp.json()["events"] == ["user.created"]

    def test_create_rejects_http_without_insecure_flag(self, test_settings):
        for url in ("http://evil.example.com/hook", "http://localhost:9000/hook"):
            client = _build(test_settings)
            resp = _create(client, url=url)
            assert resp.status_code == 400, resp.text
            assert "http" in resp.json()["detail"]
            assert "insecure" in resp.json()["detail"]

    def test_create_allows_http_with_insecure_flag(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, url="http://localhost:9000/hook", insecure=True)
        assert resp.status_code == 201, resp.text
        assert resp.json()["insecure"] is True

    def test_create_rejects_bare_scheme_placeholders(self, test_settings):
        """'http://' / 'https://' senza hostname non sono URL validi."""
        for url in ("http://", "https://"):
            client = _build(test_settings)
            resp = _create(client, url=url, insecure=True)
            assert resp.status_code == 400, resp.text
            assert "hostname" in resp.json()["detail"]

    def test_create_defaults_to_secure(self, test_settings):
        client = _build(test_settings)
        resp = _create(client)
        assert resp.status_code == 201
        assert resp.json()["insecure"] is False
        listed = client.get("/api/admin/webhooks").json()
        assert listed[0]["insecure"] is False


class TestUpdateDeleteRotate:
    def _seed(self, client):
        return _create(client).json()

    def test_patch_toggles_active(self, test_settings):
        client = _build(test_settings)
        wh = self._seed(client)

        patched = client.patch(
            f"/api/admin/webhooks/{wh['id']}", json={"active": False}
        )
        assert patched.status_code == 200
        assert patched.json()["active"] is False

    def test_patch_http_url_without_flag_rejected_on_secure_webhook(self, test_settings):
        """PATCH del solo url http su endpoint secure → 400 (combo effettiva)."""
        client = _build(test_settings)
        wh = self._seed(client)

        resp = client.patch(f"/api/admin/webhooks/{wh['id']}", json={"url": "http://x.example/h"})
        assert resp.status_code == 400
        # L'endpoint conserva url e stato insecure originali.
        detail = client.get(f"/api/admin/webhooks/{wh['id']}").json()
        assert detail["url"] == wh["url"]
        assert detail["insecure"] is False

    def test_patch_insecure_false_rejected_while_url_stays_http(self, test_settings):
        """Spegnere il flag su un endpoint http esistente → 400."""
        client = _build(test_settings)
        wh = _create(client, url="http://10.0.0.5/hook", insecure=True).json()

        resp = client.patch(f"/api/admin/webhooks/{wh['id']}", json={"insecure": False})
        assert resp.status_code == 400
        detail = client.get(f"/api/admin/webhooks/{wh['id']}").json()
        assert detail["insecure"] is True

    def test_patch_can_move_http_endpoint_to_https_and_drop_flag(self, test_settings):
        client = _build(test_settings)
        wh = _create(client, url="http://localhost:9000/hook", insecure=True).json()

        resp = client.patch(
            f"/api/admin/webhooks/{wh['id']}",
            json={"url": "https://x.example/hook", "insecure": False},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["url"] == "https://x.example/hook"
        assert body["insecure"] is False

    def test_patch_bare_placeholder_url_rejected_even_with_flag(self, test_settings):
        client = _build(test_settings)
        wh = self._seed(client)
        resp = client.patch(
            f"/api/admin/webhooks/{wh['id']}", json={"url": "http://", "insecure": True}
        )
        assert resp.status_code == 400

    def test_patch_missing_returns_404(self, test_settings):
        client = _build(test_settings)
        resp = client.patch("/api/admin/webhooks/wh_nope0000001", json={"active": False})
        assert resp.status_code == 404

    def test_delete_removes_then_404s(self, test_settings):
        client = _build(test_settings)
        wh = self._seed(client)

        deleted = client.delete(f"/api/admin/webhooks/{wh['id']}")
        assert deleted.status_code == 204
        again = client.delete(f"/api/admin/webhooks/{wh['id']}")
        assert again.status_code == 404
        assert client.get(f"/api/admin/webhooks/{wh['id']}").status_code == 404

    def test_rotate_returns_new_plaintext_secret_once(self, test_settings):
        client = _build(test_settings)
        wh = self._seed(client)
        old_masked = wh["masked_secret"]

        rotated = client.post(f"/api/admin/webhooks/{wh['id']}/rotate-secret")
        assert rotated.status_code == 200
        new_body = rotated.json()
        assert new_body["secret"].startswith("whsec_")
        assert new_body["secret"] != wh["secret"]

        # The stored masked prefix now matches the NEW secret.
        detail = client.get(f"/api/admin/webhooks/{wh['id']}").json()
        assert detail["masked_secret"] == new_body["masked_secret"]
        assert detail["masked_secret"] != old_masked

    def test_rotate_missing_returns_404(self, test_settings):
        client = _build(test_settings)
        resp = client.post("/api/admin/webhooks/wh_nope0000001/rotate-secret")
        assert resp.status_code == 404


def test_openapi_schema_generates():
    """Regression: the webhook repository factories are FastAPI dependencies.

    FastAPI introspects their signatures while building the OpenAPI schema.
    They must not expose an unresolvable ``settings`` forward reference (or
    any request parameter) or ``/openapi.json`` raises a ``PydanticUserError``.
    """
    app = FastAPI()
    app.include_router(router)

    assert TestClient(app).get("/openapi.json").status_code == 200

