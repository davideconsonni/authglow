import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from authglow.core.datetime import utcnow
from authglow.models.api_key import APIKeyCreate


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestAPIKeyCreateModel:
    def test_user_email_field_accepted(self):
        """APIKeyCreate model accepts optional user_email field."""
        key_data = APIKeyCreate(
            name="Test Key", scopes=["read"], never_expires=True, user_email="target@example.com"
        )
        assert key_data.user_email == "target@example.com"

    def test_user_email_field_defaults_none(self):
        """APIKeyCreate model defaults user_email to None."""
        key_data = APIKeyCreate(name="Test Key", scopes=["read"], never_expires=True)
        assert key_data.user_email is None

    def test_user_email_field_exceeds_max_length(self):
        """APIKeyCreate rejects user_email over 254 chars."""
        long_email = "a" * 250 + "@example.com"
        with pytest.raises(Exception):
            APIKeyCreate(
                name="Test Key", scopes=["read"], user_email=long_email, never_expires=True
            )


class TestAPIKeyLifecycle:
    def test_create_api_key(self, api_key_service):
        key_data = APIKeyCreate(name="Test Key", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-1", key_data=key_data, created_by="admin-1"
            )
        )
        assert api_key is not None
        assert api_key.name == "Test Key"
        assert api_key.key_prefix == plaintext[:12]
        assert api_key.is_active is True
        assert plaintext.startswith("ak_")

    def test_validate_api_key(self, api_key_service):
        key_data = APIKeyCreate(name="Validate Key", scopes=["read", "write"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-2", key_data=key_data, created_by="admin-1"
            )
        )
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        assert validated.key_id == api_key.key_id

    def test_validate_api_key_wrong_key(self, api_key_service):
        key_data = APIKeyCreate(name="Wrong Key Test", scopes=["read"], never_expires=True)
        _run(
            api_key_service.create_key(
                user_id="user-api-3", key_data=key_data, created_by="admin-1"
            )
        )
        validated = _run(api_key_service.validate_key("ak_wrongkey1234567890123456789"))
        assert validated is None

    def test_revoke_api_key(self, api_key_service):
        key_data = APIKeyCreate(name="Revoke Key", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-4", key_data=key_data, created_by="admin-1"
            )
        )
        revoked = _run(api_key_service.revoke_key(api_key.key_id, "admin-1"))
        assert revoked is True
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is None

    def test_api_key_prefix_format(self, api_key_service):
        key_data = APIKeyCreate(name="Prefix Key", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-5", key_data=key_data, created_by="admin-1"
            )
        )
        assert plaintext.startswith("ak_")
        assert len(plaintext) > 20
        assert len(api_key.key_prefix) == 12


class TestAPIKeyPrefixIndex:
    def test_create_key_writes_prefix_index(self, api_key_service):
        key_data = APIKeyCreate(name="Index Key", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-idx-1", key_data=key_data, created_by="admin-1"
            )
        )
        prefix = api_key.key_prefix
        index_ids = _run(api_key_service._repo.load_prefix_index(prefix))
        assert api_key.key_id in index_ids

    def test_validate_uses_prefix_index_only(self, api_key_service):
        key_data = APIKeyCreate(name="Prefix Lookup", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-idx-2", key_data=key_data, created_by="admin-1"
            )
        )
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        assert validated.key_id == api_key.key_id
        prefix = plaintext[:12]
        index_ids = _run(api_key_service._repo.load_prefix_index(prefix))
        assert api_key.key_id in index_ids

    def test_validate_invalid_prefix_returns_none_quickly(self, api_key_service):
        key_data = APIKeyCreate(name="Quick Reject", scopes=["read"], never_expires=True)
        _run(
            api_key_service.create_key(
                user_id="user-idx-3", key_data=key_data, created_by="admin-1"
            )
        )
        fake_key = "ak_nonexistent_prefix_that_is_12c"
        index_ids = _run(api_key_service._repo.load_prefix_index(fake_key[:12]))
        assert index_ids == []
        validated = _run(api_key_service.validate_key(fake_key))
        assert validated is None

    def test_delete_key_removes_from_prefix_index(self, api_key_service):
        key_data = APIKeyCreate(name="Delete Index", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-idx-4", key_data=key_data, created_by="admin-1"
            )
        )
        prefix = api_key.key_prefix
        assert api_key.key_id in _run(api_key_service._repo.load_prefix_index(prefix))

        deleted = _run(api_key_service.delete_key(api_key.key_id))
        assert deleted is True
        assert _run(api_key_service._repo.load_prefix_index(prefix)) == []

        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is None

    def test_validate_expired_key_returns_none(self, api_key_service):
        key_data = APIKeyCreate(
            name="Expired Key", scopes=["read"], expires_in_days=1, never_expires=False
        )
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-exp", key_data=key_data, created_by="admin-1"
            )
        )
        api_key.expires_at = utcnow() - timedelta(days=2)

        _run(api_key_service._repo.update(api_key))

        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is None

    def test_prefix_index_handles_prefix_collision(self, api_key_service):
        key_data_a = APIKeyCreate(name="Collision A", scopes=["read"], never_expires=True)
        key_data_b = APIKeyCreate(name="Collision B", scopes=["read"], never_expires=True)
        api_a, _ = _run(
            api_key_service.create_key(
                user_id="user-col-1", key_data=key_data_a, created_by="admin-1"
            )
        )
        api_b, _ = _run(
            api_key_service.create_key(
                user_id="user-col-2", key_data=key_data_b, created_by="admin-1"
            )
        )
        assert api_a.key_prefix != api_b.key_prefix, (
            "Collision extremely unlikely with 12-char prefix from token_urlsafe"
        )
        prefix_a_ids = _run(api_key_service._repo.load_prefix_index(api_a.key_prefix))
        assert api_a.key_id in prefix_a_ids
        assert api_b.key_id not in prefix_a_ids


class TestAPIKeyIPRestrictions:
    def test_track_usage_with_ip_restriction(self, api_key_service):
        key_data = APIKeyCreate(
            name="IP Restricted Key",
            scopes=["read"],
            never_expires=True,
            allowed_ips=["192.168.1.100"],
        )
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-api-ip", key_data=key_data, created_by="admin-1"
            )
        )
        result = _run(api_key_service.track_usage(api_key.key_id, ip_address="192.168.1.100"))
        assert result is True

    def test_track_usage_blocked_ip(self, api_key_service):
        key_data = APIKeyCreate(
            name="IP Blocked Key",
            scopes=["read"],
            never_expires=True,
            allowed_ips=["192.168.1.100"],
        )
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-api-ip2", key_data=key_data, created_by="admin-1"
            )
        )
        result = _run(api_key_service.track_usage(api_key.key_id, ip_address="10.0.0.1"))
        assert result is False


class TestAPIKeyBruteForceLockout:
    def test_record_failed_validation_increments_counter(self, api_key_service):
        key_data = APIKeyCreate(name="Lockout Key", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-lock-1", key_data=key_data, created_by="admin-1"
            )
        )
        _run(api_key_service.record_failed_validation(api_key.key_id))
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 1

    def test_key_locked_after_max_attempts(self, api_key_service):
        key_data = APIKeyCreate(name="Lockout Max", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-lock-2", key_data=key_data, created_by="admin-1"
            )
        )
        for _ in range(5):
            _run(api_key_service.record_failed_validation(api_key.key_id))
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 5
        assert key.locked_until is not None
        assert _run(api_key_service.is_key_locked(api_key.key_id)) is True

    def test_key_not_locked_below_threshold(self, api_key_service):
        key_data = APIKeyCreate(name="Lockout Below", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-lock-3", key_data=key_data, created_by="admin-1"
            )
        )
        for _ in range(4):
            _run(api_key_service.record_failed_validation(api_key.key_id))
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 4
        assert key.locked_until is None
        assert _run(api_key_service.is_key_locked(api_key.key_id)) is False

    def test_is_key_locked_auto_unlock_on_expiry(self, api_key_service):
        key_data = APIKeyCreate(name="Auto Unlock", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-lock-4", key_data=key_data, created_by="admin-1"
            )
        )
        api_key.failed_validation_attempts = 5
        api_key.locked_until = utcnow() - timedelta(minutes=1)
        _run(api_key_service._repo.update(api_key))
        assert _run(api_key_service.is_key_locked(api_key.key_id)) is False
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.locked_until is None
        assert key.failed_validation_attempts == 0

    def test_reset_failed_validations_clears_lock(self, api_key_service):
        key_data = APIKeyCreate(name="Reset Lock", scopes=["read"], never_expires=True)
        api_key, _ = _run(
            api_key_service.create_key(
                user_id="user-lock-5", key_data=key_data, created_by="admin-1"
            )
        )
        for _ in range(5):
            _run(api_key_service.record_failed_validation(api_key.key_id))
        assert _run(api_key_service.is_key_locked(api_key.key_id)) is True
        _run(api_key_service.reset_failed_validations(api_key.key_id))
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 0
        assert key.locked_until is None
        assert _run(api_key_service.is_key_locked(api_key.key_id)) is False

    def test_validate_key_records_failed_and_locks(self, api_key_service):
        key_data = APIKeyCreate(name="Validate Lock", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-lock-6", key_data=key_data, created_by="admin-1"
            )
        )
        wrong_key = plaintext[:-4] + "xxxx"
        for _ in range(5):
            result = _run(api_key_service.validate_key(wrong_key))
            assert result is None
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 5
        assert key.locked_until is not None

    def test_validate_key_raises_locked_exception(self, api_key_service):
        from authglow.services.api_key import APIKeyLockedException

        key_data = APIKeyCreate(name="Raise Locked", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-lock-7", key_data=key_data, created_by="admin-1"
            )
        )
        wrong_key = plaintext[:-4] + "xxxx"
        for _ in range(5):
            _run(api_key_service.validate_key(wrong_key))
        with pytest.raises(APIKeyLockedException) as exc_info:
            _run(api_key_service.validate_key(wrong_key))
        assert exc_info.value.key_id == api_key.key_id

    def test_validate_key_resets_on_success(self, api_key_service):
        key_data = APIKeyCreate(name="Reset On Success", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-lock-8", key_data=key_data, created_by="admin-1"
            )
        )
        wrong_key = plaintext[:-4] + "xxxx"
        for _ in range(3):
            _run(api_key_service.validate_key(wrong_key))
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 3
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 0
        assert key.locked_until is None

    def test_validate_key_invalid_prefix_no_crash(self, api_key_service):
        fake_key = "ak_nonexistent_prefix_that_is_12c"
        result = _run(api_key_service.validate_key(fake_key))
        assert result is None

    def test_validate_key_real_prefix_wrong_bcrypt(self, api_key_service):
        key_data = APIKeyCreate(name="Wrong Bcrypt", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-lock-9", key_data=key_data, created_by="admin-1"
            )
        )
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 0
        wrong_key = plaintext[:-4] + "xxxx"
        result = _run(api_key_service.validate_key(wrong_key))
        assert result is None
        key = _run(api_key_service.get_key(api_key.key_id))
        assert key.failed_validation_attempts == 1

    def test_locked_key_auto_unlock_allows_retry(self, api_key_service):
        key_data = APIKeyCreate(name="Auto Retry", scopes=["read"], never_expires=True)
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-lock-10", key_data=key_data, created_by="admin-1"
            )
        )
        api_key.failed_validation_attempts = 5
        api_key.locked_until = utcnow() - timedelta(minutes=1)
        _run(api_key_service._repo.update(api_key))
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        assert validated.key_id == api_key.key_id


class TestAdminCreatesKeyForOtherUser:
    """Admin can pass user_email to create an API key for another user."""

    def test_admin_creates_key_for_other_user(self, test_settings):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.api_key import router
        from authglow.api.auth import get_api_key_service, get_audit_service, get_current_user
        from authglow.models.user import User
        from authglow.services.password import hash_password

        admin_user = User(
            id="admin-test-1",
            email="admin@authglow.io",
            hashed_password=hash_password("NotUsed123!"),
            is_active=True,
            scopes=["read", "write", "admin"],
        )
        target_user = User(
            id="target-user-1",
            email="target@example.com",
            hashed_password=hash_password("NotUsed123!"),
            is_active=True,
            scopes=["read"],
        )

        app = FastAPI()
        app.include_router(router)

        async def override_get_current_user():
            return admin_user

        app.dependency_overrides[get_current_user] = override_get_current_user

        async def override_get_api_key_service():
            from datetime import timezone

            svc = AsyncMock()
            created_key = MagicMock()
            created_key.key_id = "key-created-001"
            created_key.name = "Admin-Created Key"
            created_key.scopes = ["read"]
            created_key.model_dump.return_value = {
                "key_id": "key-created-001",
                "user_id": "target-user-1",
                "name": "Admin-Created Key",
                "description": None,
                "scopes": ["read"],
                "key_prefix": "ak_test12",
                "key_hash": "hash",
                "is_active": True,
                "never_expires": True,
                "expires_at": None,
                "last_used_at": None,
                "total_requests": 0,
                "created_at": datetime(2026, 6, 4, tzinfo=timezone.utc),
                "created_by": "admin-test-1",
                "allowed_ips": [],
            }
            svc.create_key = AsyncMock(return_value=(created_key, "ak_admincreated123456789"))
            return svc

        app.dependency_overrides[get_api_key_service] = override_get_api_key_service

        async def override_get_audit_service():
            svc = AsyncMock()
            svc.log_event = AsyncMock()
            return svc

        app.dependency_overrides[get_audit_service] = override_get_audit_service

        with patch("authglow.services.user.UserService.get_user_by_email") as mock_lookup:
            mock_lookup.return_value = target_user

            client = TestClient(app)
            response = client.post(
                "/api/keys",
                json={
                    "name": "Admin-Created Key",
                    "scopes": ["read"],
                    "never_expires": True,
                    "user_email": "target@example.com",
                },
            )

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["user_id"] == "target-user-1"
        assert "api_key" in body

    def test_non_admin_cannot_specify_user_email(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.api_key import router
        from authglow.api.auth import get_api_key_service, get_audit_service, get_current_user
        from authglow.models.user import User
        from authglow.services.password import hash_password

        regular_user = User(
            id="regular-user-1",
            email="regular@authglow.io",
            hashed_password=hash_password("NotUsed123!"),
            is_active=True,
            scopes=["read"],
        )

        app = FastAPI()
        app.include_router(router)

        async def override_get_current_user():
            return regular_user

        app.dependency_overrides[get_current_user] = override_get_current_user

        async def override_get_api_key_service():
            return AsyncMock()

        app.dependency_overrides[get_api_key_service] = override_get_api_key_service

        async def override_get_audit_service():
            svc = AsyncMock()
            svc.log_event = AsyncMock()
            return svc

        app.dependency_overrides[get_audit_service] = override_get_audit_service

        client = TestClient(app)
        response = client.post(
            "/api/keys",
            json={
                "name": "Unauthorized Key",
                "scopes": ["read"],
                "never_expires": True,
                "user_email": "target@example.com",
            },
        )

        assert response.status_code == 403
        assert "admin" in response.json()["detail"].lower()

    def test_admin_gets_404_for_unknown_user_email(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.api_key import router
        from authglow.api.auth import get_api_key_service, get_audit_service, get_current_user
        from authglow.models.user import User
        from authglow.services.password import hash_password

        admin_user = User(
            id="admin-test-2",
            email="admin@authglow.io",
            hashed_password=hash_password("NotUsed123!"),
            is_active=True,
            scopes=["read", "write", "admin"],
        )

        app = FastAPI()
        app.include_router(router)

        async def override_get_current_user():
            return admin_user

        app.dependency_overrides[get_current_user] = override_get_current_user

        async def override_get_api_key_service():
            return AsyncMock()

        app.dependency_overrides[get_api_key_service] = override_get_api_key_service

        async def override_get_audit_service():
            svc = AsyncMock()
            svc.log_event = AsyncMock()
            return svc

        app.dependency_overrides[get_audit_service] = override_get_audit_service

        with patch("authglow.services.user.UserService.get_user_by_email") as mock_lookup:
            mock_lookup.return_value = None

            client = TestClient(app)
            response = client.post(
                "/api/keys",
                json={
                    "name": "Missing User Key",
                    "scopes": ["read"],
                    "never_expires": True,
                    "user_email": "nobody@example.com",
                },
            )

        assert response.status_code == 404
        assert "nobody@example.com" in response.json()["detail"]

    def test_user_creates_key_for_self_without_email(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.api_key import router
        from authglow.api.auth import get_api_key_service, get_audit_service, get_current_user
        from authglow.models.user import User
        from authglow.services.password import hash_password

        regular_user = User(
            id="regular-user-2",
            email="regular@authglow.io",
            hashed_password=hash_password("NotUsed123!"),
            is_active=True,
            scopes=["read"],
        )

        app = FastAPI()
        app.include_router(router)

        async def override_get_current_user():
            return regular_user

        app.dependency_overrides[get_current_user] = override_get_current_user

        async def override_get_api_key_service():
            from datetime import timezone

            svc = AsyncMock()
            created_key = MagicMock()
            created_key.key_id = "self-key-001"
            created_key.name = "Self Key"
            created_key.scopes = ["read"]
            created_key.model_dump.return_value = {
                "key_id": "self-key-001",
                "user_id": "regular-user-2",
                "name": "Self Key",
                "description": None,
                "scopes": ["read"],
                "key_prefix": "ak_self12",
                "key_hash": "hash",
                "is_active": True,
                "never_expires": True,
                "expires_at": None,
                "last_used_at": None,
                "total_requests": 0,
                "created_at": datetime(2026, 6, 4, tzinfo=timezone.utc),
                "created_by": "regular-user-2",
                "allowed_ips": [],
            }
            svc.create_key = AsyncMock(return_value=(created_key, "ak_selfservice123456789"))
            return svc

        app.dependency_overrides[get_api_key_service] = override_get_api_key_service

        async def override_get_audit_service():
            svc = AsyncMock()
            svc.log_event = AsyncMock()
            return svc

        app.dependency_overrides[get_audit_service] = override_get_audit_service

        client = TestClient(app)
        response = client.post(
            "/api/keys",
            json={
                "name": "Self Key",
                "scopes": ["read"],
                "never_expires": True,
            },
        )

        assert response.status_code == 201, response.text
        body = response.json()
        assert body["user_id"] == "regular-user-2"
