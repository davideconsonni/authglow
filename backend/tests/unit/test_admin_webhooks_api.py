"""API tests for the admin Webhook Endpoints CRUD (initiative B, B1).

Exercises the real ``FileWebhookRepository`` against per-test tmp storage
(same integration-style pattern as the claim-policy API tests), with
``require_admin`` bypassed via dependency override.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.webhooks import get_webhook_repository, require_admin, router
from authglow.models.user import User
from authglow.repositories.file.webhook import FileWebhookRepository

ADMIN = User(
    id="admin-1",
    email="admin@example.com",
    hashed_password="not-a-real-hash",
    is_active=True,
    email_verified=True,
    scopes=["admin", "read", "write"],
)


def _build(test_settings):
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_admin] = lambda: ADMIN
    app.dependency_overrides[get_webhook_repository] = lambda: FileWebhookRepository(
        settings=test_settings
    )
    return TestClient(app)


DEFAULT_EVENTS = ["user.created"]


def _create(client, url="https://example.com/hook", events=None):
    body = {
        "url": url,
        # ``None`` → default catalog entry; an explicit ``[]`` is passed
        # through so the rejection path can be tested.
        "events": DEFAULT_EVENTS if events is None else events,
    }
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

    def test_create_enforces_https_for_remote_urls(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, url="http://evil.example.com/hook")
        assert resp.status_code == 400
        assert "https" in resp.json()["detail"]

    def test_create_allows_localhost_http(self, test_settings):
        client = _build(test_settings)
        resp = _create(client, url="http://localhost:9000/hook")
        assert resp.status_code == 201


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
