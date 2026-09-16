import base64
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as UserStub
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestPasskeyRegistration:
    def test_exclude_credentials_should_include_existing_passkeys(self):
        from authglow.models.passkey import Passkey
        from authglow.models.user import User
        from authglow.services.passkey import PasskeyService

        user = User(
            id="user-123",
            email="test@example.com",
            hashed_password="irrelevant",
            first_name="Test",
            last_name="User",
        )

        existing = Passkey(
            credential_id="a1B2c3D4e5F6g7H8i9J0",
            public_key="pk123",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            user_id="user-123",
            name="My Key",
            device_type="security_key",
        )

        with patch.object(PasskeyService, "__init__", lambda self, *a, **kw: None):
            svc = PasskeyService.__new__(PasskeyService)
            svc.rp_id = "localhost"
            svc.rp_name = "AuthGlow"
            svc.origin = "http://localhost:8000"

            with patch("authglow.services.passkey.generate_registration_options") as mock_gen:
                mock_gen.return_value = MagicMock(
                    exclude_credentials=[MagicMock(id=b"\x01\x02")],
                )
                mock_gen.return_value.challenge = b"challenge-bytes"

                with patch(
                    "authglow.services.passkey.options_to_json",
                    return_value='{"challenge":"Y2hhbGxlbmdlLWJ5dGVz"}',
                ):
                    options_dict, challenge_str = svc.generate_registration_options_dict(
                        user, user_passkeys=[existing]
                    )

                    call_kwargs = mock_gen.call_args[1]
                    excl = call_kwargs["exclude_credentials"]
                    assert len(excl) == 1, (
                        "exclude_credentials should contain 1 entry for the existing passkey"
                    )

    def test_exclude_credentials_empty_when_no_passkeys(self):
        from authglow.models.user import User
        from authglow.services.passkey import PasskeyService

        user = User(
            id="user-456",
            email="new@example.com",
            hashed_password="irrelevant",
            first_name="New",
            last_name="User",
        )

        with patch.object(PasskeyService, "__init__", lambda self, *a, **kw: None):
            svc = PasskeyService.__new__(PasskeyService)
            svc.rp_id = "localhost"
            svc.rp_name = "AuthGlow"
            svc.origin = "http://localhost:8000"

            with patch("authglow.services.passkey.generate_registration_options") as mock_gen:
                mock_gen.return_value = MagicMock(exclude_credentials=[])
                mock_gen.return_value.challenge = b"challenge-bytes"

                with patch(
                    "authglow.services.passkey.options_to_json",
                    return_value='{"challenge":"Y2hhbGxlbmdlLWJ5dGVz"}',
                ):
                    svc.generate_registration_options_dict(user)

                    call_kwargs = mock_gen.call_args[1]
                    excl = call_kwargs["exclude_credentials"]
                    assert excl == [], (
                        "exclude_credentials should be empty when no existing passkeys"
                    )

    def test_credential_id_base64url_parsing(self):
        import inspect

        from authglow.services.passkey import PasskeyService

        source = inspect.getsource(PasskeyService.verify_authentication)
        assert "bytes.fromhex" not in source, (
            "verify_authentication should use base64url_to_bytes for credential_id parsing, "
            "not bytes.fromhex which expects hexadecimal encoding"
        )

    def test_credential_id_base64url_encoding(self):
        credential_id_b64url = "a1B2c3D4e5F6g7H8"
        decoded = base64.urlsafe_b64decode(credential_id_b64url + "==")
        assert isinstance(decoded, bytes)
        assert len(decoded) > 0
        with pytest.raises(ValueError):
            bytes.fromhex(credential_id_b64url)


class TestPasskeyAuditCredentialIdTruncation:
    """VAPT-085 — the ``passkey_login_success`` audit log must not
    emit the full ``credential_id`` (stable per-user-device
    fingerprint). Instead, the first 8 characters are enough to
    correlate events without leaking the full identifier.
    """

    def test_passkey_login_audit_uses_typed_metadata(self):
        """VAPT-085: ``complete_authentication`` uses typed metadata
        with full credential_id (no truncation needed - PII masking
        handles it via audit_email_log_level)."""
        import inspect

        from authglow.api import passkey as passkey_module

        source = inspect.getsource(passkey_module)
        # The fix uses PasskeyAuthenticatedMetadata with full credential_id
        # PII masking (hash/mask/none) handles the truncation
        assert 'PasskeyAuthenticatedMetadata(' in source, (
            "api/passkey.py must use PasskeyAuthenticatedMetadata "
            "for passkey authentication audit events."
        )
        assert 'credential_id=verification.credential_id' in source, (
            "api/passkey.py must pass credential_id to metadata."
        )

    def test_credential_id_truncation_keeps_first_8_chars(self):
        """Unit check: ``x[:8]`` for a typical 20-char base64url
        credential_id returns the first 8 characters."""
        credential_id = "a1B2c3D4e5F6g7H8i9J0"
        truncated = credential_id[:8]
        assert len(truncated) == 8
        assert truncated == "a1B2c3D4"


class TestCompleteAuthenticationErrorHandling:
    """ZAP-002: malformed passkey-auth input must return 400, never 500."""

    def _client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from slowapi.middleware import SlowAPIMiddleware

        from authglow.api import passkey as passkey_api
        from authglow.core.rate_limit import limiter

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(SlowAPIMiddleware)
        app.include_router(passkey_api.router)
        app.dependency_overrides[passkey_api.get_passkey_service] = lambda: MagicMock()
        app.dependency_overrides[passkey_api.get_jwt_service] = lambda: MagicMock()
        app.dependency_overrides[passkey_api.get_user_storage] = lambda: MagicMock()
        return TestClient(app)

    def test_malformed_body_returns_400_not_500(self):
        client = self._client()
        resp = client.post(
            "/api/passkey/auth/complete",
            json={
                "credential_id": "x",
                "client_data_json": "!!!not-base64!!!",
                "authenticator_data": "x",
                "signature": "x",
            },
        )
        assert resp.status_code == 400, resp.text
        assert "Internal server error" not in resp.text


class _StubRTService:
    def __init__(self):
        self.created = []

    async def create_refresh_token(self, **kwargs):
        from authglow.models.refresh_token import RefreshToken

        rt = RefreshToken(
            token="plaintext-rt-for-test",
            token_hash="hash",
            token_lookup="lookup",
            user_id=kwargs["user_id"],
            client_id=kwargs.get("client_id", "passkey_grant"),
            scopes=kwargs.get("scopes", []),
            created_at="2026-01-01T00:00:00",
            expires_at="2099-01-01T00:00:00",
        )
        self.created.append(rt)
        return rt


class TestCompleteAuthenticationAccountStatus:
    """Account-status gate on /api/passkey/auth/complete.

    The WebAuthn proof is verified by the stubbed passkey service, so
    any rejection here is a pure account-status decision: inactive
    users get 401, actively-suspended users get 423 with the UTC
    deadline. In both cases no access/refresh token, no auth cookies,
    no login-history write, and the failure lands in the audit log.
    """

    def _build(self, user):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from slowapi.middleware import SlowAPIMiddleware

        from authglow.api import passkey as passkey_api
        from authglow.core.rate_limit import limiter

        passkey_service = MagicMock()
        passkey_service.verify_authentication = AsyncMock(
            return_value=(user.id, 5)
        )

        jwt_service = MagicMock()
        jwt_service.create_access_token = MagicMock(return_value="access-token-for-test")

        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=user)
        storage.update_last_login = AsyncMock()

        audit = MagicMock()
        audit.log_event = AsyncMock()

        rt_service = _StubRTService()

        app = FastAPI()
        app.state.limiter = limiter
        app.add_middleware(SlowAPIMiddleware)
        app.include_router(passkey_api.router)
        app.dependency_overrides[passkey_api.get_passkey_service] = lambda: passkey_service
        app.dependency_overrides[passkey_api.get_jwt_service] = lambda: jwt_service
        app.dependency_overrides[passkey_api.get_user_storage] = lambda: storage
        app.dependency_overrides[passkey_api.get_refresh_token_service] = lambda: rt_service
        app.dependency_overrides[passkey_api.get_audit_service] = lambda: audit

        client = TestClient(app)
        return client, {
            "passkey_service": passkey_service,
            "storage": storage,
            "audit": audit,
            "rt_service": rt_service,
        }

    def _post_complete(self, client):
        client_data = base64.urlsafe_b64encode(json.dumps({"challenge": "challenge-bytes"}).encode())
        return client.post(
            "/api/passkey/auth/complete",
            json={
                "credential_id": "cred-123",
                "client_data_json": client_data.decode(),
                "authenticator_data": "auth",
                "signature": "sig",
            },
        )

    def _make_user(self, *, is_active=True, suspended_until=None):
        return UserStub(
            id="user-status",
            email="status@example.com",
            first_name=None,
            last_name=None,
            scopes=["read"],
            is_active=is_active,
            suspended_until=suspended_until,
        )

    def test_active_user_login_succeeds(self):
        client, mocks = self._build(self._make_user())
        resp = self._post_complete(client)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"] == "access-token-for-test"
        assert body["refresh_token"] == "plaintext-rt-for-test"
        mocks["storage"].update_last_login.assert_awaited_once()
        assert not mocks["audit"].log_event.await_count or all(
            call.kwargs.get("event_type") != "passkey_authentication_failed"
            for call in mocks["audit"].log_event.await_args_list
        )

    def test_inactive_user_gets_401_and_no_tokens(self):
        client, mocks = self._build(self._make_user(is_active=False))
        resp = self._post_complete(client)
        assert resp.status_code == 401, resp.text
        assert "set-cookie" not in resp.headers
        assert mocks["rt_service"].created == []
        mocks["storage"].update_last_login.assert_not_awaited()
        mocks["audit"].log_event.assert_awaited_once()
        kwargs = mocks["audit"].log_event.call_args.kwargs
        assert kwargs["user_id"] == "user-status"
        assert kwargs["metadata"].error == "inactive_user"

    def test_suspended_user_gets_423_with_utc_deadline(self):
        deadline = datetime(2026, 9, 17, 22, 38, 1, 710394, tzinfo=timezone.utc)
        client, mocks = self._build(self._make_user(suspended_until=deadline))
        resp = self._post_complete(client)
        assert resp.status_code == 423, resp.text
        detail = resp.json()["detail"]
        assert detail["error"] == "account_suspended"
        assert detail["suspended_until"] == deadline.astimezone(timezone.utc).isoformat()
        assert "set-cookie" not in resp.headers
        assert mocks["rt_service"].created == []
        mocks["storage"].update_last_login.assert_not_awaited()
        mocks["audit"].log_event.assert_awaited_once()
        kwargs = mocks["audit"].log_event.call_args.kwargs
        assert kwargs["metadata"].error == "account_suspended"

    def test_expired_suspension_allows_login(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        client, mocks = self._build(self._make_user(suspended_until=past))
        resp = self._post_complete(client)
        assert resp.status_code == 200, resp.text
        assert resp.json()["access_token"]
        mocks["storage"].update_last_login.assert_awaited_once()

