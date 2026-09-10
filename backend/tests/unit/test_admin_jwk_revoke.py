"""Regression: ``POST /api/admin/jwk-keys/{kid}/revoke`` must AWAIT
``JWTService.revoke_key``.

Pre-fix, the endpoint called ``success = jwt_service.revoke_key(kid)``
WITHOUT ``await``: a coroutine object was created but never run. Because a
coroutine object is truthy, even the ``if not success`` 400 branch was
masked — the endpoint returned 200 and logged a SUCCESS audit event for a
revocation that never persisted. Surfaced live as::

    RuntimeWarning: coroutine 'JWTService.revoke_key' was never awaited
"""

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

# Module-level authglow imports (not function-local): the
# ``from authglow.core.config import get_settings`` bindings inside
# these modules must resolve at COLLECTION time (unpatched). If the
# first import happens at runtime while ``_override_settings`` has
# ``get_settings`` patched, the binding freezes on that test's mock
# and every later test reads a stale ``test_settings`` (auth 401s).
import authglow.api.admin  # noqa: F401
import authglow.services.rbac  # noqa: F401


def _build_app():
    """TestClient app authenticated as the persisted RBAC admin (the
    caller passes ``admin_auth_headers`` to ``TestClient``) with the
    audit service mocked."""
    from authglow.api.admin import get_audit_service, router

    app = FastAPI()
    app.include_router(router)

    audit = MagicMock()
    audit.log_event = AsyncMock()
    app.dependency_overrides[get_audit_service] = lambda: audit
    return app, audit


def _patched_jwt_service(success: bool):
    svc = MagicMock()
    svc.revoke_key = AsyncMock(return_value=success)
    return (
        patch("authglow.api.admin.get_jwt_service", AsyncMock(return_value=svc)),
        svc,
    )


class TestRevokeJwkKeyAwaitRegression:
    def test_source_awaits_revoke_key(self):
        """Source-level antiregression: the await must stay in place."""
        from authglow.api.admin import revoke_jwk_key

        source = inspect.getsource(revoke_jwk_key)
        assert "await jwt_service.revoke_key(kid)" in source, (
            "revoke_jwk_key must AWAIT jwt_service.revoke_key — an un-awaited "
            "coroutine silently no-op'd revocations (RuntimeWarning + fake 200)"
        )

    def test_revoke_awaits_persists_and_audits(self, test_settings, admin_auth_headers):
        app, audit = _build_app()
        cm, svc = _patched_jwt_service(success=True)

        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app, headers=admin_auth_headers)
            resp = client.post("/api/admin/jwk-keys/kid-123/revoke")

        assert resp.status_code == 200, resp.text
        assert resp.json()["message"] == "JWK key kid-123 revoked successfully"
        svc.revoke_key.assert_awaited_once_with("kid-123")
        audit.log_event.assert_awaited_once()
        assert audit.log_event.await_args.kwargs["event_type"] == "jwk_key_revoked"

    def test_revoke_failure_returns_400(self, test_settings, admin_auth_headers):
        """Active key / unknown kid → 400, no success audit event."""
        app, audit = _build_app()
        cm, svc = _patched_jwt_service(success=False)

        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app, headers=admin_auth_headers)
            resp = client.post("/api/admin/jwk-keys/active-kid/revoke")

        assert resp.status_code == 400, resp.text
        assert "Cannot revoke key" in resp.json()["detail"]
        svc.revoke_key.assert_awaited_once_with("active-kid")
        audit.log_event.assert_not_awaited()


class TestRotateJwkKeysSafeword:
    """Safeword-gated ``POST /api/admin/jwk-keys/rotate`` handshake."""

    def _build_app(self):
        return _build_app()

    def _mock_jwt_rotate(self, old_kid="old-1", new_kid="new-2"):
        svc = MagicMock()
        svc.rotate_keys = AsyncMock(
            return_value={"old_kid": old_kid, "new_kid": new_kid}
        )
        return patch("authglow.api.admin.get_jwt_service", AsyncMock(return_value=svc)), svc

    def test_rotate_without_safeword_returns_400(self, test_settings, admin_auth_headers):
        app, audit = self._build_app()
        cm, svc = self._mock_jwt_rotate()
        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app, headers=admin_auth_headers)
            resp = client.post("/api/admin/jwk-keys/rotate", json={})
        assert resp.status_code in (400, 422), resp.text
        svc.rotate_keys.assert_not_awaited()
        audit.log_event.assert_not_awaited()

    def test_rotate_with_valid_safeword_succeeds(self, test_settings, admin_auth_headers):
        app, audit = self._build_app()
        cm, svc = self._mock_jwt_rotate()
        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app, headers=admin_auth_headers)
            challenge = client.post("/api/admin/jwk-keys/rotate/challenge").json()
            resp = client.post(
                "/api/admin/jwk-keys/rotate",
                json={
                    "challenge_id": challenge["challenge_id"],
                    "word": challenge["word"],
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["old_kid"] == "old-1"
        assert body["new_kid"] == "new-2"
        svc.rotate_keys.assert_awaited_once()
        audit.log_event.assert_awaited_once()

    def test_rotate_with_wrong_safeword_returns_400(self, test_settings, admin_auth_headers):
        app, audit = self._build_app()
        cm, svc = self._mock_jwt_rotate()
        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app, headers=admin_auth_headers)
            challenge = client.post("/api/admin/jwk-keys/rotate/challenge").json()
            resp = client.post(
                "/api/admin/jwk-keys/rotate",
                json={
                    "challenge_id": challenge["challenge_id"],
                    "word": "wrong-word-99",
                },
            )
        assert resp.status_code == 400, resp.text
        svc.rotate_keys.assert_not_awaited()
