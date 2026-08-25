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


def _build_app():
    """TestClient with require_admin bypassed and the audit service mocked."""
    from authglow.api.admin import get_audit_service, require_admin, router
    from authglow.models.user import User

    app = FastAPI()
    app.include_router(router)

    admin = User(
        id="admin-1",
        email="admin@example.com",
        hashed_password="not-a-real-hash",
        is_active=True,
        email_verified=True,
        scopes=["admin"],
    )
    app.dependency_overrides[require_admin] = lambda: admin

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

    def test_revoke_awaits_persists_and_audits(self, test_settings):
        app, audit = _build_app()
        cm, svc = _patched_jwt_service(success=True)

        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app)
            resp = client.post("/api/admin/jwk-keys/kid-123/revoke")

        assert resp.status_code == 200, resp.text
        assert resp.json()["message"] == "JWK key kid-123 revoked successfully"
        svc.revoke_key.assert_awaited_once_with("kid-123")
        audit.log_event.assert_awaited_once()
        assert audit.log_event.await_args.kwargs["event_type"] == "jwk_key_revoked"

    def test_revoke_failure_returns_400(self, test_settings):
        """Active key / unknown kid → 400, no success audit event."""
        app, audit = _build_app()
        cm, svc = _patched_jwt_service(success=False)

        with cm, patch("authglow.api.admin.get_settings", return_value=test_settings):
            client = TestClient(app)
            resp = client.post("/api/admin/jwk-keys/active-kid/revoke")

        assert resp.status_code == 400, resp.text
        assert "Cannot revoke key" in resp.json()["detail"]
        svc.revoke_key.assert_awaited_once_with("active-kid")
        audit.log_event.assert_not_awaited()
