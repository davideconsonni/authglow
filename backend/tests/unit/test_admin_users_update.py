import pytest
from unittest.mock import patch, AsyncMock
from fastapi import Request


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

    def test_bootstrap_admin_cannot_be_deactivated(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.is_bootstrap = True
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(is_active=False)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                update_user(
                    user_id="user-to-update",
                    update_data=update_data,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 400
        mock_storage.update_user.assert_not_called()

    def test_bootstrap_admin_can_still_be_updated_and_activated(self):
        import asyncio
        from authglow.api.admin import update_user
        from authglow.models.admin import UserUpdate

        existing = _make_existing_user()
        existing.is_bootstrap = True
        existing.is_active = True
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        update_data = UserUpdate(first_name="NewFirst", is_active=True)

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
        assert result.is_active is True


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


class TestBulkUserOperationBootstrap:
    def test_bulk_deactivate_skips_bootstrap_admin(self):
        import asyncio
        from authglow.api.admin import bulk_user_operation
        from authglow.models.admin import BulkUserOperation

        admin = _make_admin_user()
        bootstrap = _make_existing_user()
        bootstrap.id = "bootstrap-id"
        bootstrap.is_bootstrap = True
        bootstrap.is_active = True

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=bootstrap)
        mock_audit = AsyncMock()

        operation = BulkUserOperation(user_ids=["bootstrap-id"], operation="deactivate")

        result = asyncio.get_event_loop().run_until_complete(
            bulk_user_operation(
                request=_make_request(),
                operation=operation,
                current_user=admin,
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["success"] == 0
        assert result["failed"] == 1
        assert "bootstrap" in result["errors"][0].lower()
        assert bootstrap.is_active is True
        mock_storage.update_user.assert_not_called()

    def test_bulk_deactivate_skips_own_account(self):
        import asyncio
        from authglow.api.admin import bulk_user_operation
        from authglow.models.admin import BulkUserOperation

        admin = _make_admin_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=admin)
        mock_audit = AsyncMock()

        operation = BulkUserOperation(user_ids=[admin.id], operation="deactivate")

        result = asyncio.get_event_loop().run_until_complete(
            bulk_user_operation(
                request=_make_request(),
                operation=operation,
                current_user=admin,
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["failed"] == 1


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
