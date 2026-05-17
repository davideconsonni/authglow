import pytest
from authglow.models.api_key import APIKeyCreate


class TestAPIKeyLifecycle:
    def test_create_api_key(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(name="Test Key", scopes=["read"], never_expires=True)
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
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
        import asyncio

        key_data = APIKeyCreate(
            name="Validate Key", scopes=["read", "write"], never_expires=True
        )
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-2", key_data=key_data, created_by="admin-1"
            )
        )
        validated = asyncio.get_event_loop().run_until_complete(
            api_key_service.validate_key(plaintext)
        )
        assert validated is not None
        assert validated.key_id == api_key.key_id

    def test_validate_api_key_wrong_key(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(
            name="Wrong Key Test", scopes=["read"], never_expires=True
        )
        asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-3", key_data=key_data, created_by="admin-1"
            )
        )
        validated = asyncio.get_event_loop().run_until_complete(
            api_key_service.validate_key("ak_wrongkey1234567890123456789")
        )
        assert validated is None

    def test_revoke_api_key(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(name="Revoke Key", scopes=["read"], never_expires=True)
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-4", key_data=key_data, created_by="admin-1"
            )
        )
        revoked = asyncio.get_event_loop().run_until_complete(
            api_key_service.revoke_key(api_key.key_id, "admin-1")
        )
        assert revoked is True
        validated = asyncio.get_event_loop().run_until_complete(
            api_key_service.validate_key(plaintext)
        )
        assert validated is None

    def test_api_key_prefix_format(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(name="Prefix Key", scopes=["read"], never_expires=True)
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-5", key_data=key_data, created_by="admin-1"
            )
        )
        assert plaintext.startswith("ak_")
        assert len(plaintext) > 20
        assert len(api_key.key_prefix) == 12


class TestAPIKeyValidationOptimization:
    def test_validate_key_uses_prefix_for_lookup(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(name="O(n) Key", scopes=["read"], never_expires=True)
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-on", key_data=key_data, created_by="admin-1"
            )
        )
        validated = asyncio.get_event_loop().run_until_complete(
            api_key_service.validate_key(plaintext)
        )
        assert validated is not None
        assert validated.key_prefix == plaintext[:12]

    def test_validate_expired_key_returns_none(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(
            name="Expired Key", scopes=["read"], expires_in_days=1, never_expires=False
        )
        api_key, plaintext = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-exp", key_data=key_data, created_by="admin-1"
            )
        )
        from datetime import datetime

        api_key.expires_at = datetime.utcnow() - timedelta(days=2)
        import json

        file_path = f"{api_key_service.storage_path}/{api_key.key_id}.json"
        with api_key_service.fs.open(file_path, "w") as f:
            json.dump(api_key.model_dump(), f, default=str)
        validated = asyncio.get_event_loop().run_until_complete(
            api_key_service.validate_key(plaintext)
        )
        assert validated is None


class TestAPIKeyIPRestrictions:
    def test_track_usage_with_ip_restriction(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(
            name="IP Restricted Key",
            scopes=["read"],
            never_expires=True,
            allowed_ips=["192.168.1.100"],
        )
        api_key, _ = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-ip", key_data=key_data, created_by="admin-1"
            )
        )
        result = asyncio.get_event_loop().run_until_complete(
            api_key_service.track_usage(api_key.key_id, ip_address="192.168.1.100")
        )
        assert result is True

    def test_track_usage_blocked_ip(self, api_key_service):
        import asyncio

        key_data = APIKeyCreate(
            name="IP Blocked Key",
            scopes=["read"],
            never_expires=True,
            allowed_ips=["192.168.1.100"],
        )
        api_key, _ = asyncio.get_event_loop().run_until_complete(
            api_key_service.create_key(
                user_id="user-api-ip2", key_data=key_data, created_by="admin-1"
            )
        )
        result = asyncio.get_event_loop().run_until_complete(
            api_key_service.track_usage(api_key.key_id, ip_address="10.0.0.1")
        )
        assert result is False


from datetime import timedelta
