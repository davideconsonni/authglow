"""Device Authorization Grant (RFC 8628) integration tests — Workstream S.

Validates the complete device authorization flow:
``POST /oauth2/device/authorize`` → ``POST /oauth2/device/token`` (polling).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


class TestDeviceFlow:
    """Device Authorization Grant end-to-end (RFC 8628)."""

    def test_device_authorize_returns_codes(self):
        """POST /oauth2/device/authorize returns device_code + user_code."""
        from datetime import datetime, timedelta, timezone

        from authglow.api import device_auth as device_module
        from authglow.api.device_auth import router
        from authglow.models.token import DeviceAuthorization

        now = datetime.now(timezone.utc)
        mock_auth = DeviceAuthorization(
            device_code="test-device-code-abc123",
            user_code="ABCD-EFGH",
            client_id="test-client",
            scope="read",
            verification_uri="http://localhost:8000/oauth2/device/verify",
            expires_at=now + timedelta(seconds=600),
            interval=5,
            status="pending",
        )

        mock_service = MagicMock()
        mock_service.create_device_authorization = AsyncMock(return_value=mock_auth)

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        with patch.object(device_module, "DeviceAuthorizationService", return_value=mock_service):
            response = http_client.post(
                "/oauth2/device/authorize",
                data={"client_id": "test-client", "scope": "read"},
            )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["device_code"] == "test-device-code-abc123"
        assert body["user_code"] == "ABCD-EFGH"
        assert "verification_uri" in body
        assert body["expires_in"] > 0
        assert body["interval"] == 5

    def test_poll_pending(self):
        """Poll before user approval returns authorization_pending."""
        from datetime import datetime, timedelta, timezone

        from authglow.api.auth import router as auth_router
        from authglow.models.token import DeviceAuthorization

        now = datetime.now(timezone.utc)
        mock_auth = DeviceAuthorization(
            device_code="test-device-code-pending",
            user_code="ABCD-EFGH",
            client_id="test-client",
            scope="read",
            verification_uri="http://localhost:8000/oauth2/device/verify",
            expires_at=now + timedelta(seconds=600),
            interval=5,
            status="pending",
        )

        mock_service = MagicMock()
        mock_service.poll = AsyncMock(return_value=mock_auth)

        app = FastAPI()
        app.include_router(auth_router)
        http_client = TestClient(app)

        with patch(
            "authglow.services.device_auth.DeviceAuthorizationService",
            return_value=mock_service,
        ):
            response = http_client.post(
                "/oauth2/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "code": "test-device-code-pending",
                    "client_id": "test-client",
                },
            )

        assert response.status_code == 400
        body = response.json()
        assert "detail" in body
        detail = body["detail"]
        if isinstance(detail, dict):
            assert detail["error"] == "authorization_pending"
        else:
            assert "authorization_pending" in str(detail)

    def test_poll_slow_down(self):
        """Polling too fast returns slow_down."""
        from datetime import datetime, timedelta, timezone

        from authglow.api.auth import router as auth_router
        from authglow.models.token import DeviceAuthorization

        now = datetime.now(timezone.utc)
        mock_auth = DeviceAuthorization(
            device_code="test-device-code-slow",
            user_code="ABCD-EFGH",
            client_id="test-client",
            scope="read",
            verification_uri="http://localhost:8000/oauth2/device/verify",
            expires_at=now + timedelta(seconds=600),
            interval=5,
            status="pending",
            last_poll_at=now,
        )

        mock_service = MagicMock()
        mock_service.poll = AsyncMock(return_value=mock_auth)

        app = FastAPI()
        app.include_router(auth_router)
        http_client = TestClient(app)

        with patch(
            "authglow.services.device_auth.DeviceAuthorizationService",
            return_value=mock_service,
        ):
            response = http_client.post(
                "/oauth2/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "code": "test-device-code-slow",
                    "client_id": "test-client",
                },
            )

        assert response.status_code == 400
        body = response.json()
        detail = body["detail"]
        if isinstance(detail, dict):
            assert detail["error"] == "slow_down"
        else:
            assert "slow_down" in str(detail)

    def test_poll_expired(self):
        """Poll after expiry returns expired_token."""
        from authglow.api.auth import router as auth_router

        mock_service = MagicMock()
        mock_service.poll = AsyncMock(return_value=None)

        app = FastAPI()
        app.include_router(auth_router)
        http_client = TestClient(app)

        with patch(
            "authglow.services.device_auth.DeviceAuthorizationService",
            return_value=mock_service,
        ):
            response = http_client.post(
                "/oauth2/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "code": "expired-code",
                    "client_id": "test-client",
                },
            )

        assert response.status_code == 400
        body = response.json()
        detail = body["detail"]
        if isinstance(detail, dict):
            assert detail["error"] == "expired_token"
        else:
            assert "expired_token" in str(detail)

    def test_poll_access_denied(self):
        """Poll after user denial returns access_denied."""
        from datetime import datetime, timedelta, timezone

        from authglow.api.auth import router as auth_router
        from authglow.models.token import DeviceAuthorization

        now = datetime.now(timezone.utc)
        mock_auth = DeviceAuthorization(
            device_code="test-device-code-denied",
            user_code="ABCD-EFGH",
            client_id="test-client",
            scope="read",
            verification_uri="http://localhost:8000/oauth2/device/verify",
            expires_at=now + timedelta(seconds=600),
            interval=5,
            status="denied",
        )

        mock_service = MagicMock()
        mock_service.poll = AsyncMock(return_value=mock_auth)

        app = FastAPI()
        app.include_router(auth_router)
        http_client = TestClient(app)

        with patch(
            "authglow.services.device_auth.DeviceAuthorizationService",
            return_value=mock_service,
        ):
            response = http_client.post(
                "/oauth2/token",
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "code": "test-device-code-denied",
                    "client_id": "test-client",
                },
            )

        assert response.status_code == 400
        body = response.json()
        detail = body["detail"]
        if isinstance(detail, dict):
            assert detail["error"] == "access_denied"
        else:
            assert "access_denied" in str(detail)
