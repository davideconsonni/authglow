"""API-level tests for the admin runtime configuration endpoints.

Covers ``PUT /api/admin/rate-limits/config`` and
``PATCH /api/admin/settings`` plus the extended
``GET /api/admin/rate-limits`` rows, using a minimal FastAPI app that
mounts the ``admin_settings`` router with ``require_admin`` overridden.
Persistence goes through the real File repositories bound to the
per-test ``test_settings`` (autouse fixture); the rate-limit service
patches the process-wide limiter singleton, so an autouse fixture
restores its ``enabled`` flag after each test.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.admin import require_admin
from authglow.api.admin_settings import router as admin_settings_router
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.repositories.file.rate_limit_config import (
    FileRateLimitConfigRepository,
)
from authglow.repositories.file.settings_override import (
    FileSettingsOverrideRepository,
)
from authglow.services.settings_override import SettingsOverrideService


@pytest.fixture(autouse=True)
def _restore_limiter_enabled():
    """The PUT endpoint mutates the process-wide limiter singleton;
    restore its enabled flag so the leak does not disable rate
    limiting for every other test in the worker."""
    limiter.enabled = True
    yield
    limiter.enabled = True


@pytest.fixture
def client(test_admin_user):
    app = FastAPI()
    app.state.limiter = limiter
    app.include_router(admin_settings_router)
    app.dependency_overrides[require_admin] = lambda: test_admin_user
    return TestClient(app)


class TestPutRateLimitsConfig:
    def test_persists_and_applies_enabled_false(self, client, test_settings):
        response = client.put(
            "/api/admin/rate-limits/config", json={"enabled": False}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is False

        # Live application: the status endpoint reads the same singleton.
        status = client.get("/api/admin/rate-limits/status").json()
        assert status["enabled"] is False

        # Persistence: a fresh repo bound to the same settings sees it.
        repo = FileRateLimitConfigRepository(settings=test_settings)

        import asyncio

        persisted = asyncio.run(repo.load())
        assert persisted is not None
        assert persisted.enabled is False

    def test_persists_override(self, client, test_settings):
        response = client.put(
            "/api/admin/rate-limits/config",
            json={"overrides": {"/api/auth/login": "5/minute"}},
        )

        assert response.status_code == 200
        assert response.json()["overrides"] == {"/api/auth/login": "5/minute"}

        import asyncio

        persisted = asyncio.run(
            FileRateLimitConfigRepository(settings=test_settings).load()
        )
        assert persisted.overrides == {"/api/auth/login": "5/minute"}

    def test_invalid_limit_rejected_with_400(self, client):
        response = client.put(
            "/api/admin/rate-limits/config",
            json={"overrides": {"/api/auth/login": "banana"}},
        )

        assert response.status_code == 400
        assert "Invalid rate limit string" in response.json()["detail"]

    def test_empty_update_rejected_with_400(self, client):
        response = client.put("/api/admin/rate-limits/config", json={})

        assert response.status_code == 400

    def test_override_removal_via_null(self, client, test_settings):
        client.put(
            "/api/admin/rate-limits/config",
            json={"overrides": {"/api/auth/login": "5/minute"}},
        )
        response = client.put(
            "/api/admin/rate-limits/config",
            json={"overrides": {"/api/auth/login": None}},
        )

        assert response.status_code == 200
        assert response.json()["overrides"] == {}

    def test_get_rate_limits_reflects_override(self, client):
        client.put(
            "/api/admin/rate-limits/config",
            json={"overrides": {"/api/admin/settings": "42/hour"}},
        )
        rows = client.get("/api/admin/rate-limits").json()["rate_limits"]

        settings_rows = [r for r in rows if r.get("path") == "/api/admin/settings"]
        assert settings_rows, "expected the /api/admin/settings route row"
        row = settings_rows[0]
        assert row["source"] == "override"
        assert row["override"] == "42/hour"


class TestPatchAdminSettings:
    def test_persists_and_applies_live(self, client, test_settings):
        response = client.patch(
            "/api/admin/settings", json={"app_name": "Renamed By Test"}
        )

        assert response.status_code == 200
        body = response.json()
        assert body["updated"] == ["app_name"]
        assert body["restart_required"] == []
        # Live application onto the patched Settings singleton.
        assert test_settings.app_name == "Renamed By Test"
        # GET reflects the new value.
        fields = {
            f["key"]: f for f in client.get("/api/admin/settings").json()["settings"]
        }
        assert fields["app_name"]["value"] == "Renamed By Test"

    def test_persists_restart_required_key(self, client, test_settings):
        response = client.patch(
            "/api/admin/settings", json={"debug": True}
        )

        assert response.status_code == 200
        assert response.json()["restart_required"] == ["debug"]

        import asyncio

        persisted = asyncio.run(
            FileSettingsOverrideRepository(settings=test_settings).load()
        )
        assert persisted == {"debug": True}
        # Persisted overrides are applied at startup by the service.
        service = SettingsOverrideService(settings=test_settings)
        import asyncio as _asyncio

        _applied = _asyncio.run(service.refresh_if_changed())
        assert _applied is True
        assert test_settings.debug is True

    def test_unknown_key_rejected_with_400(self, client):
        response = client.patch(
            "/api/admin/settings", json={"no_such_key": "x"}
        )
        assert response.status_code == 400

    def test_secret_key_rejected_with_400(self, client):
        """``secret_key`` is in ``_EXCLUDED_FIELDS`` — never editable."""
        response = client.patch(
            "/api/admin/settings", json={"secret_key": "attacker-key"}
        )
        assert response.status_code == 400

    def test_type_mismatch_rejected_with_400(self, client):
        response = client.patch(
            "/api/admin/settings", json={"debug": "yes-please"}
        )
        assert response.status_code == 400

    def test_fields_expose_editable_flag(self, client):
        fields = client.get("/api/admin/settings").json()["settings"]
        assert fields, "expected exposed settings"
        assert all(f["editable"] is True for f in fields)
