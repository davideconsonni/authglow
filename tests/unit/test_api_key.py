import json
import asyncio
import pytest
from datetime import datetime, timedelta
from authglow.models.api_key import APIKeyCreate
from authglow.core.datetime import utcnow


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


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
        key_data = APIKeyCreate(
            name="Validate Key", scopes=["read", "write"], never_expires=True
        )
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-api-2", key_data=key_data, created_by="admin-1"
            )
        )
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        assert validated.key_id == api_key.key_id

    def test_validate_api_key_wrong_key(self, api_key_service):
        key_data = APIKeyCreate(
            name="Wrong Key Test", scopes=["read"], never_expires=True
        )
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
        index_ids = _run(api_key_service._load_prefix_index(prefix))
        assert api_key.key_id in index_ids

    def test_validate_uses_prefix_index_only(self, api_key_service):
        key_data = APIKeyCreate(
            name="Prefix Lookup", scopes=["read"], never_expires=True
        )
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-idx-2", key_data=key_data, created_by="admin-1"
            )
        )
        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is not None
        assert validated.key_id == api_key.key_id
        prefix = plaintext[:12]
        index_ids = _run(api_key_service._load_prefix_index(prefix))
        assert api_key.key_id in index_ids

    def test_validate_invalid_prefix_returns_none_quickly(self, api_key_service):
        key_data = APIKeyCreate(
            name="Quick Reject", scopes=["read"], never_expires=True
        )
        _run(
            api_key_service.create_key(
                user_id="user-idx-3", key_data=key_data, created_by="admin-1"
            )
        )
        fake_key = "ak_nonexistent_prefix_that_is_12c"
        index_ids = _run(api_key_service._load_prefix_index(fake_key[:12]))
        assert index_ids == []
        validated = _run(api_key_service.validate_key(fake_key))
        assert validated is None

    def test_delete_key_removes_from_prefix_index(self, api_key_service):
        key_data = APIKeyCreate(
            name="Delete Index", scopes=["read"], never_expires=True
        )
        api_key, plaintext = _run(
            api_key_service.create_key(
                user_id="user-idx-4", key_data=key_data, created_by="admin-1"
            )
        )
        prefix = api_key.key_prefix
        assert api_key.key_id in _run(api_key_service._load_prefix_index(prefix))

        deleted = _run(api_key_service.delete_key(api_key.key_id))
        assert deleted is True
        assert _run(api_key_service._load_prefix_index(prefix)) == []

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

        _run(
            api_key_service._afs.write_json(
                f"{api_key_service.storage_path}/{api_key.key_id}.json",
                api_key.model_dump(),
                default=str,
            )
        )

        validated = _run(api_key_service.validate_key(plaintext))
        assert validated is None

    def test_prefix_index_handles_prefix_collision(self, api_key_service):
        key_data_a = APIKeyCreate(
            name="Collision A", scopes=["read"], never_expires=True
        )
        key_data_b = APIKeyCreate(
            name="Collision B", scopes=["read"], never_expires=True
        )
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
        prefix_a_ids = _run(api_key_service._load_prefix_index(api_a.key_prefix))
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
        result = _run(
            api_key_service.track_usage(api_key.key_id, ip_address="192.168.1.100")
        )
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
        result = _run(
            api_key_service.track_usage(api_key.key_id, ip_address="10.0.0.1")
        )
        assert result is False
