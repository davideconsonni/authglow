import asyncio

import pytest
from unittest.mock import patch, AsyncMock
from fastapi import Request

asyncio.set_event_loop(asyncio.new_event_loop())


def _make_admin_user():
    from authglow.models.user import User

    return User(
        id="admin-test-1",
        email="admin@authglow.io",
        hashed_password="not-used-in-test",
        is_active=True,
        scopes=["admin"],
    )


def _make_existing_user():
    from authglow.models.user import User

    return User(
        id="user-to-update",
        email="existing@example.com",
        hashed_password="hashed-password-here",
        is_active=True,
        email_verified=False,
        first_name="OldFirst",
        last_name="OldLast",
        scopes=["read", "write"],
    )


def _make_request():
    """Create a minimal Request with the state that slowapi's limiter expects."""
    request = Request({"type": "http", "method": "PUT", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


class TestUpdateUserFields:
    def test_update_first_name(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="NewFirst")

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.first_name == "NewFirst"
        assert result.last_name == "OldLast"
        assert result.email == "existing@example.com"

    def test_update_last_name(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(last_name="NewLast")

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.last_name == "NewLast"
        assert result.first_name == "OldFirst"

    def test_update_email_verified(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.email_verified = False
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(email_verified=True)

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.email_verified is True

    def test_update_partial_does_not_clear_other_fields(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.scopes = ["read", "write", "admin"]
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="OnlyFirst")

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.first_name == "OnlyFirst"
        assert result.last_name == "OldLast"
        assert result.is_active is True
        assert result.scopes == ["read", "write", "admin"]

    def test_update_all_fields_at_once(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(
            first_name="NewFirst",
            last_name="NewLast",
            email_verified=True,
            scopes=["admin"],
            is_active=False,
        )

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.first_name == "NewFirst"
        assert result.last_name == "NewLast"
        assert result.email_verified is True
        assert result.is_active is False
        assert result.scopes == ["admin"]

    def test_update_nonexistent_user_returns_404(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="NewFirst")

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                update_user(
                    user_id="nonexistent-id",
                    update_data=update_data,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404


class TestUpdateUserScopes:
    def test_update_scopes_replaces_list(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.scopes = ["read", "write"]
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(scopes=["admin", "read"])

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.scopes == ["admin", "read"]

    def test_empty_scopes_clears_list(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.scopes = ["read", "write"]
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(scopes=[])

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.scopes == []

    def test_scopes_unchanged_when_not_provided(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.scopes = ["read", "write"]
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="OnlyFirst")

        result = asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result.scopes == ["read", "write"]


class TestUpdateUserAuditLogging:
    def test_update_logs_audit_event(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="NewFirst")

        asyncio.get_event_loop().run_until_complete(
            update_user(
                user_id="user-to-update",
                update_data=update_data,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "user_updated"
        assert call_kwargs["metadata"]["target_user_id"] == "user-to-update"
        assert call_kwargs["metadata"]["changes"]["first_name"] == "NewFirst"
