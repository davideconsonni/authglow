"""Device Authorization Grant (RFC 8628) integration tests — Workstream S
+ A2 hardening.

Validates the complete device authorization flow:

``POST /oauth2/device/authorize`` (client-validated)
  → ``POST /oauth2/token`` polling (top-level RFC 8628 §3.5 errors,
    interval escalation, ownership check, opaque rotated refresh tokens).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.token import Token

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _public_client():
    client = MagicMock()
    client.is_confidential = False
    client.is_active = True
    client.dpop_bound = False
    client.grant_types = ["authorization_code", "refresh_token", DEVICE_GRANT]
    return client


def _mock_oauth2_service():
    svc = MagicMock()
    client = _public_client()
    svc.client_storage.get_client = AsyncMock(return_value=client)
    svc.verify_client = AsyncMock(return_value=True)
    svc.verify_grant_type = AsyncMock(return_value=True)
    svc.process_scopes = AsyncMock(side_effect=lambda cid, scopes: list(scopes))
    return svc


def _pending_auth(**overrides):
    from authglow.models.token import DeviceAuthorization

    now = datetime.now(timezone.utc)
    fields = dict(
        device_code="test-device-code",
        user_code="ABCD-EFGH",
        client_id="test-client",
        scope="read",
        verification_uri="http://localhost:8000/oauth2/device/verify",
        expires_at=now + timedelta(seconds=600),
        interval=5,
        status="pending",
    )
    fields.update(overrides)
    return DeviceAuthorization(**fields)


def _token_app(mock_device_service):
    """Bare app with the auth router; both backing services mocked."""
    from authglow.api.auth import get_oauth2_service, get_user_storage
    from authglow.api.auth import router as auth_router
    from authglow.api.oauth_errors import register_oauth2_error_handler

    oauth2_svc = _mock_oauth2_service()

    app = FastAPI()
    register_oauth2_error_handler(app)
    app.include_router(auth_router)
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_svc
    app.dependency_overrides[get_user_storage] = lambda: MagicMock()

    http_client = TestClient(app)
    return http_client, oauth2_svc


def _poll(http_client):
    return http_client.post(
        "/oauth2/token",
        data={
            "grant_type": DEVICE_GRANT,
            "code": "test-device-code",
            "client_id": "test-client",
        },
    )


class TestDeviceAuthorizeEndpoint:
    def test_device_authorize_returns_codes(self):
        from authglow.api import device_auth as device_module
        from authglow.api.device_auth import router

        mock_auth = _pending_auth(device_code="test-device-code-abc123")
        mock_service = MagicMock()
        mock_service.create_device_authorization = AsyncMock(return_value=mock_auth)

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        with (
            patch.object(
                device_module, "DeviceAuthorizationService", return_value=mock_service
            ),
            patch.object(device_module, "OAuth2Service", return_value=_mock_oauth2_service()),
        ):
            response = http_client.post(
                "/oauth2/device/authorize",
                data={"client_id": "test-client", "scope": "read"},
            )

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["device_code"] == "test-device-code-abc123"
        assert body["user_code"] == "ABCD-EFGH"
        assert body["interval"] == 5

    def test_unknown_client_rejected(self):
        from fastapi import FastAPI as F

        from authglow.api import device_auth as device_module
        from authglow.api.device_auth import router
        from authglow.api.oauth_errors import register_oauth2_error_handler

        svc = _mock_oauth2_service()
        svc.client_storage.get_client = AsyncMock(return_value=None)

        app = F()
        register_oauth2_error_handler(app)
        app.include_router(router)
        http = TestClient(app)

        with (
            patch.object(
                device_module, "DeviceAuthorizationService", return_value=MagicMock()
            ),
            patch.object(device_module, "OAuth2Service", return_value=svc),
        ):
            res = http.post(
                "/oauth2/device/authorize",
                data={"client_id": "ghost", "scope": "read"},
            )

        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"

    def test_unregistered_grant_rejected(self):
        from fastapi import FastAPI as F

        from authglow.api import device_auth as device_module
        from authglow.api.device_auth import router
        from authglow.api.oauth_errors import register_oauth2_error_handler

        svc = _mock_oauth2_service()
        # Registration WITHOUT the device grant.
        svc.client_storage.get_client.return_value.grant_types = [
            "authorization_code",
            "refresh_token",
        ]

        app = F()
        register_oauth2_error_handler(app)
        app.include_router(router)
        http = TestClient(app)

        with (
            patch.object(
                device_module, "DeviceAuthorizationService", return_value=MagicMock()
            ),
            patch.object(device_module, "OAuth2Service", return_value=svc),
        ):
            res = http.post(
                "/oauth2/device/authorize",
                data={"client_id": "test-client", "scope": "read"},
            )

        assert res.status_code == 400
        body = res.json()
        assert body["error"] == "unauthorized_client"
        assert DEVICE_GRANT in body["error_description"]

    def test_scope_filtered_through_process_scopes(self, test_settings):
        from authglow.api import device_auth as device_module
        from authglow.api.device_auth import router

        mock_auth = _pending_auth(scope="read admin")
        mock_service = MagicMock()
        mock_service.create_device_authorization = AsyncMock(return_value=mock_auth)

        svc = _mock_oauth2_service()
        svc.process_scopes = AsyncMock(return_value=["read"])

        app = FastAPI()
        app.include_router(router)
        http = TestClient(app)

        expected_uri = f"{(test_settings.frontend_base_url or 'http://testserver').rstrip('/')}/oauth2/device/verify"

        with (
            patch.object(
                device_module, "DeviceAuthorizationService", return_value=mock_service
            ),
            patch.object(device_module, "OAuth2Service", return_value=svc),
        ):
            res = http.post(
                "/oauth2/device/authorize",
                data={"client_id": "test-client", "scope": "read admin"},
            )

        assert res.status_code == 200
        # The stored scope must be the PROCESSED one.
        mock_service.create_device_authorization.assert_awaited_once_with(
            "test-client", "read", expected_uri
        )


class TestDeviceTokenPolling:
    def test_poll_pending(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(return_value=_pending_auth())
        mock_service.escalate_interval = AsyncMock(return_value=10)

        http, _ = _token_app(mock_service)
        with patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service):
            response = _poll(http)

        assert response.status_code == 400
        assert response.json()["error"] == "authorization_pending"

    def test_poll_slow_down_escalates_interval(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        now = datetime.now(timezone.utc)
        auth = _pending_auth(last_poll_at=now)
        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(return_value=auth)
        mock_service.escalate_interval = AsyncMock(return_value=10)

        http, _ = _token_app(mock_service)
        with patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service):
            response = _poll(http)

        assert response.status_code == 400
        body = response.json()
        assert body["error"] == "slow_down"
        # RFC 8628 §3.5: the interval MUST be escalated on slow_down.
        mock_service.escalate_interval.assert_awaited_once_with("test-device-code")

    def test_poll_expired(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(return_value=None)

        http, _ = _token_app(mock_service)
        with patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service):
            response = _poll(http)

        assert response.status_code == 400
        assert response.json()["error"] == "expired_token"

    def test_poll_access_denied(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(return_value=_pending_auth(status="denied"))

        http, _ = _token_app(mock_service)
        with patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service):
            response = _poll(http)

        assert response.status_code == 400
        assert response.json()["error"] == "access_denied"

    def test_wrong_client_cannot_redeem(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(
            return_value=_pending_auth(client_id="legit-client", status="authorized", user_id="u1")
        )

        http, _ = _token_app(mock_service)
        with patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service):
            response = _poll(http)

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    def test_authorized_returns_opaque_refresh_token(self):
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        user = MagicMock(id="user-1", email="u@x.com", scopes=["read"], is_active=True)
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=user)

        jwt_svc = MagicMock()
        expected = Token(access_token="at-fake", token_type="Bearer", expires_in=300)
        jwt_svc.create_token_response = MagicMock(return_value=expected)

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(
            return_value=_pending_auth(
                status="authorized", user_id="user-1", scope="read offline_access"
            )
        )
        mock_service.cleanup_expired = AsyncMock(return_value=0)

        http, oauth2_svc = _token_app(mock_service)
        from authglow.api.auth import get_jwt_service as gjs
        from authglow.api.auth import get_user_storage as gus

        http.app.dependency_overrides[gus] = lambda: storage
        http.app.dependency_overrides[gjs] = lambda: jwt_svc

        claim_policy = MagicMock()
        claim_policy.build_claims = AsyncMock(return_value={})

        rt_instance = MagicMock()
        rt_instance.create_refresh_token = AsyncMock(return_value=MagicMock(token="rt-opaque-value"))

        with (
            patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service),
            patch("authglow.api.auth.ClaimPolicyService", return_value=claim_policy),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_instance),
        ):
            response = _poll(http)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["access_token"] == "at-fake"
        # Opaque rotated refresh token — never a JWT.
        assert body["refresh_token"] == "rt-opaque-value"
        assert "." not in body["refresh_token"]

    def test_authorized_without_offline_access_skips_refresh_token(self):
        """OIDC Core §11: the device branch issues a refresh token only
        when ``offline_access`` was granted — otherwise the response is
        access-token-only (no error)."""
        from authglow.services.device_auth import DeviceAuthorizationService as Svc

        user = MagicMock(id="user-1", email="u@x.com", scopes=["read"], is_active=True)
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=user)

        jwt_svc = MagicMock()
        expected = Token(access_token="at-fake", token_type="Bearer", expires_in=300)
        jwt_svc.create_token_response = MagicMock(return_value=expected)

        mock_service = MagicMock(spec=Svc)
        mock_service.poll = AsyncMock(
            return_value=_pending_auth(status="authorized", user_id="user-1")
        )
        mock_service.cleanup_expired = AsyncMock(return_value=0)

        http, _ = _token_app(mock_service)
        from authglow.api.auth import get_jwt_service as gjs
        from authglow.api.auth import get_user_storage as gus

        http.app.dependency_overrides[gus] = lambda: storage
        http.app.dependency_overrides[gjs] = lambda: jwt_svc

        claim_policy = MagicMock()
        claim_policy.build_claims = AsyncMock(return_value={})

        rt_instance = MagicMock()
        rt_instance.create_refresh_token = AsyncMock(
            return_value=MagicMock(token="rt-opaque-value")
        )

        with (
            patch("authglow.services.device_auth.DeviceAuthorizationService", return_value=mock_service),
            patch("authglow.api.auth.ClaimPolicyService", return_value=claim_policy),
            patch("authglow.api.auth.RefreshTokenService", return_value=rt_instance),
        ):
            response = _poll(http)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["access_token"] == "at-fake"
        assert body["refresh_token"] is None
        rt_instance.create_refresh_token.assert_not_awaited()
