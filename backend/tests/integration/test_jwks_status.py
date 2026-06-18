"""JWKS Status endpoint integration tests — Workstream R.

Validates that ``GET /oauth2/jwks/status`` returns the full
keyring with ``status`` for every ``kid``, including revoked
keys that are hidden from ``/.well-known/jwks.json``.
"""

from unittest.mock import MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app():
    """Build a standalone FastAPI app with the oidc router."""
    from authglow.api.oidc import router

    app = FastAPI()
    app.include_router(router)
    return app


class TestJwksStatus:
    """GET /oauth2/jwks/status — full keyring with status per kid."""

    def test_active_key_status(self):
        """Key with status=active is returned with status="active"."""
        from authglow.api import oidc as oidc_module

        mock_jwt = MagicMock()
        mock_jwt.get_keyring_info.return_value = {
            "active_kid": "k20260618000001",
            "keys": {
                "k20260618000001": {
                    "created_at": "2026-06-18T00:00:01+00:00",
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": 2048,
                },
            },
        }

        app = _build_app()
        http_client = TestClient(app)

        with patch.object(oidc_module, "JWTService", return_value=mock_jwt):
            response = http_client.get("/oauth2/jwks/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["active_kid"] == "k20260618000001"
        assert len(body["keys"]) == 1
        key = body["keys"][0]
        assert key["kid"] == "k20260618000001"
        assert key["status"] == "active"
        assert key["algorithm"] == "RS256"
        assert key["key_size"] == 2048
        assert key["created_at"] == "2026-06-18T00:00:01+00:00"

    def test_verifying_key_status(self):
        """Key with status=verifying is returned with status="verifying"."""
        from authglow.api import oidc as oidc_module

        mock_jwt = MagicMock()
        mock_jwt.get_keyring_info.return_value = {
            "active_kid": "k20260618000001",
            "keys": {
                "k20260618000001": {
                    "created_at": "2026-06-18T00:00:01+00:00",
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": 2048,
                },
                "k20260617000001": {
                    "created_at": "2026-06-17T00:00:01+00:00",
                    "status": "verifying",
                    "algorithm": "RS256",
                    "key_size": 2048,
                    "retired_at": "2026-06-18T00:00:01+00:00",
                },
            },
        }

        app = _build_app()
        http_client = TestClient(app)

        with patch.object(oidc_module, "JWTService", return_value=mock_jwt):
            response = http_client.get("/oauth2/jwks/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["keys"]) == 2

        verifying = [k for k in body["keys"] if k["status"] == "verifying"]
        assert len(verifying) == 1
        assert verifying[0]["kid"] == "k20260617000001"
        assert verifying[0]["retired_at"] == "2026-06-18T00:00:01+00:00"

    def test_revoked_key_status(self):
        """Key with status=revoked is returned with status="revoked"."""
        from authglow.api import oidc as oidc_module

        mock_jwt = MagicMock()
        mock_jwt.get_keyring_info.return_value = {
            "active_kid": "k20260618000001",
            "keys": {
                "k20260618000001": {
                    "created_at": "2026-06-18T00:00:01+00:00",
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": 2048,
                },
                "k20260616000001": {
                    "created_at": "2026-06-16T00:00:01+00:00",
                    "status": "revoked",
                    "algorithm": "RS256",
                    "key_size": 2048,
                    "retired_at": "2026-06-17T00:00:01+00:00",
                    "revoked_at": "2026-06-18T00:00:01+00:00",
                },
            },
        }

        app = _build_app()
        http_client = TestClient(app)

        with patch.object(oidc_module, "JWTService", return_value=mock_jwt):
            response = http_client.get("/oauth2/jwks/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert len(body["keys"]) == 2

        revoked = [k for k in body["keys"] if k["status"] == "revoked"]
        assert len(revoked) == 1
        assert revoked[0]["kid"] == "k20260616000001"
        assert revoked[0]["retired_at"] == "2026-06-17T00:00:01+00:00"
        assert revoked[0]["revoked_at"] == "2026-06-18T00:00:01+00:00"

    def test_all_keys_present(self):
        """All keys in the keyring are returned (active + verifying + revoked)."""
        from authglow.api import oidc as oidc_module

        mock_jwt = MagicMock()
        mock_jwt.get_keyring_info.return_value = {
            "active_kid": "k-active",
            "keys": {
                "k-active": {
                    "created_at": "2026-06-18T10:00:00+00:00",
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": 2048,
                },
                "k-verifying": {
                    "created_at": "2026-05-18T10:00:00+00:00",
                    "status": "verifying",
                    "algorithm": "RS256",
                    "key_size": 2048,
                    "retired_at": "2026-06-18T10:00:00+00:00",
                },
                "k-revoked": {
                    "created_at": "2026-04-18T10:00:00+00:00",
                    "status": "revoked",
                    "algorithm": "RS256",
                    "key_size": 2048,
                    "retired_at": "2026-05-18T10:00:00+00:00",
                    "revoked_at": "2026-06-18T10:00:00+00:00",
                },
            },
        }

        app = _build_app()
        http_client = TestClient(app)

        with patch.object(oidc_module, "JWTService", return_value=mock_jwt):
            response = http_client.get("/oauth2/jwks/status")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["active_kid"] == "k-active"
        assert len(body["keys"]) == 3

        statuses = {k["kid"]: k["status"] for k in body["keys"]}
        assert statuses == {
            "k-active": "active",
            "k-verifying": "verifying",
            "k-revoked": "revoked",
        }

    def test_rate_limit_header(self):
        """GET /oauth2/jwks/status has a rate-limit decorator."""
        from authglow.api.oidc import jwks_status
        from authglow.core.rate_limit import limiter

        key = f"{jwks_status.__module__}.{jwks_status.__name__}"
        limits_obj = limiter._route_limits.get(key, [])
        limits = [str(lo.limit) for lo in limits_obj]
        assert len(limits) > 0, "jwks_status has no rate-limit decorator"
