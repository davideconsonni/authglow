"""Execution tests for ``authglow.api.admin`` mutations (COV-BE-018).

Slice 2 of COV-BE-017: the heavy mutation handlers — admin user
create/update/delete, MFA and password operations, bulk operations,
data export and the refresh-token revoke failure branch. Handlers are
called directly with ``AsyncMock`` collaborators; limiter-decorated
handlers get a real Starlette ``Request``.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException

from authglow.api import admin as admin_mod
from authglow.core.datetime import utcnow
from authglow.services.admin_action import AdminActionService
from authglow.services.login_history import LoginHistoryService
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.passkey import PasskeyService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.security_event import SecurityEventService

_STRONG_PASSWORD = "Abcdefgh123!"


def _admin():
    from authglow.models.user import User

    return User(
        id="admin-1",
        email="admin@example.com",
        hashed_password="x",
        is_active=True,
        scopes=["read", "write"],
    )


def _target(**overrides):
    from authglow.models.user import User

    data = {
        "id": "target-1",
        "email": "target@example.com",
        "hashed_password": "x",
        "is_active": True,
        "email_verified": False,
        "first_name": "T",
        "last_name": "U",
        "scopes": ["read"],
    }
    data.update(overrides)
    return User(**data)


def _request():
    from fastapi import Request

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "",
            "headers": [],
            "client": ("127.0.0.1", 1234),
        }
    )
    request.state.view_rate_limit = None
    return request


def _audit():
    audit = MagicMock()
    audit.log_event = AsyncMock()
    return audit


def _recorders():
    return (
        patch.object(AdminActionService, "record_action", new=AsyncMock()),
        patch.object(SecurityEventService, "record_event", new=AsyncMock()),
    )


def _storage_for_returning(user):
    storage = MagicMock()
    storage.get_user = AsyncMock(return_value=user)
    storage.update_user = AsyncMock(return_value=user)
    storage.delete_user = AsyncMock()
    return storage


class TestUpdateUserEmailChange:
    async def test_email_change_sends_verification(self):
        from authglow.models.admin import UserUpdate

        updated = _target(email="new@example.com")
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        storage.update_email = AsyncMock(return_value=updated)
        verification = MagicMock()
        verification.create_verification_token = AsyncMock(
            return_value=SimpleNamespace(verification_code="code")
        )
        verification.send_verification_email = AsyncMock()
        action, event = _recorders()
        with (
            patch.object(admin_mod, "EmailVerificationService", return_value=verification),
            action,
            event,
        ):
            await admin_mod.update_user(
                user_id="target-1",
                update_data=UserUpdate(email="new@example.com", email_verified=False),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        storage.update_email.assert_awaited_once()
        verification.create_verification_token.assert_awaited_once()
        verification.send_verification_email.assert_awaited_once()

    async def test_email_change_verified_skips_verification(self):
        from authglow.models.admin import UserUpdate

        updated = _target(email="new@example.com")
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        storage.update_email = AsyncMock(return_value=updated)
        verification = MagicMock()
        verification.create_verification_token = AsyncMock()
        verification.send_verification_email = AsyncMock()
        action, event = _recorders()
        with (
            patch.object(admin_mod, "EmailVerificationService", return_value=verification),
            action,
            event,
        ):
            await admin_mod.update_user(
                user_id="target-1",
                update_data=UserUpdate(email="new@example.com", email_verified=True),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        verification.create_verification_token.assert_not_awaited()
        verification.send_verification_email.assert_not_awaited()

    async def test_email_change_user_vanishes_404(self):
        from authglow.models.admin import UserUpdate

        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        storage.update_email = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.update_user(
                user_id="target-1",
                update_data=UserUpdate(email="new@example.com"),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 404


class TestCreateUser:
    def _storage(self, created):
        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=None)
        storage.create_user = AsyncMock(return_value=created)
        return storage

    async def test_create_with_roles_assigns_and_audits(self):
        from authglow.models.user import UserCreate

        created = _target(id="new-1", email="new@example.com", email_verified=True)
        storage = self._storage(created)
        audit = _audit()
        rbac = MagicMock()
        rbac.assign_role_names_to_user = AsyncMock(return_value=["admin"])
        action, event = _recorders()
        with (
            patch.object(admin_mod, "RBACService", return_value=rbac),
            action,
            event,
        ):
            out = await admin_mod.create_user(
                body=UserCreate(
                    email="new@example.com",
                    password=_STRONG_PASSWORD,
                    roles=["admin"],
                    email_verified=True,
                ),
                current_user=_admin(),
                storage=storage,
                audit_service=audit,
            )
        assert out.id == "new-1"
        rbac.assign_role_names_to_user.assert_awaited_once()
        assert audit.log_event.await_count == 2

    async def test_create_unverified_sends_verification(self):
        from authglow.models.user import UserCreate

        created = _target(id="new-2", email="new2@example.com")
        storage = self._storage(created)
        verification = MagicMock()
        verification.create_verification_token = AsyncMock(
            return_value=SimpleNamespace(verification_code="code")
        )
        verification.send_verification_email = AsyncMock()
        action, event = _recorders()
        with (
            patch.object(admin_mod, "EmailVerificationService", return_value=verification),
            action,
            event,
        ):
            await admin_mod.create_user(
                body=UserCreate(
                    email="new2@example.com",
                    password=_STRONG_PASSWORD,
                    email_verified=False,
                ),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        verification.send_verification_email.assert_awaited_once()

    async def test_duplicate_email_400(self):
        from authglow.models.user import UserCreate

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=_target())
        with pytest.raises(HTTPException) as exc:
            await admin_mod.create_user(
                body=UserCreate(email="target@example.com", password=_STRONG_PASSWORD),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400

    async def test_weak_password_400(self):
        from authglow.models.user import UserCreate

        storage = self._storage(_target())
        with pytest.raises(HTTPException) as exc:
            await admin_mod.create_user(
                body=UserCreate(email="new@example.com", password="aaaaaaaa"),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400

    async def test_storage_value_error_400(self):
        from authglow.models.user import UserCreate

        storage = self._storage(_target())
        storage.create_user = AsyncMock(side_effect=ValueError("duplicate"))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.create_user(
                body=UserCreate(email="new@example.com", password=_STRONG_PASSWORD),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400

    async def test_unknown_role_400(self):
        from authglow.models.user import UserCreate

        created = _target(id="new-3", email="new3@example.com", email_verified=True)
        storage = self._storage(created)
        rbac = MagicMock()
        rbac.assign_role_names_to_user = AsyncMock(side_effect=ValueError("unknown role"))
        action, event = _recorders()
        with (
            patch.object(admin_mod, "RBACService", return_value=rbac),
            action,
            event,
        ):
            with pytest.raises(HTTPException) as exc:
                await admin_mod.create_user(
                    body=UserCreate(
                        email="new3@example.com",
                        password=_STRONG_PASSWORD,
                        roles=["nope"],
                        email_verified=True,
                    ),
                    current_user=_admin(),
                    storage=storage,
                    audit_service=_audit(),
                )
        assert exc.value.status_code == 400


class TestDeleteUserGuards:
    async def test_delete_self_400(self):
        with pytest.raises(HTTPException) as exc:
            await admin_mod.delete_user(
                request=_request(),
                user_id="admin-1",
                current_user=_admin(),
                storage=MagicMock(),
                audit_service=_audit(),
                mfa_service=MagicMock(),
            )
        assert exc.value.status_code == 400

    async def test_delete_missing_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.delete_user(
                request=_request(),
                user_id="nope",
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
                mfa_service=MagicMock(),
            )
        assert exc.value.status_code == 404


class TestMfaAndPasswordGuards:
    async def test_reset_mfa_missing_user_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.reset_user_mfa(
                request=_request(),
                user_id="nope",
                background_tasks=BackgroundTasks(),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
                mfa_service=MagicMock(),
            )
        assert exc.value.status_code == 404

    async def test_disable_mfa_federated_400(self):
        storage = _storage_for_returning(_target(mfa_enabled=True, is_federated=True))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.disable_user_mfa(
                request=_request(),
                user_id="target-1",
                background_tasks=BackgroundTasks(),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
                mfa_service=MagicMock(),
            )
        assert exc.value.status_code == 400

    async def test_regenerate_backup_codes_federated_400(self):
        storage = _storage_for_returning(_target(is_federated=True))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.regenerate_user_backup_codes(
                user_id="target-1",
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
                mfa_service=MagicMock(),
            )
        assert exc.value.status_code == 400

    async def test_set_password_not_updated_404(self):
        from authglow.models.admin import SetPasswordRequest

        storage = _storage_for_returning(_target())
        storage.set_password = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.set_user_password(
                request=_request(),
                user_id="target-1",
                body=SetPasswordRequest(password=_STRONG_PASSWORD),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 404

    async def test_send_password_reset_federated_400(self):
        storage = _storage_for_returning(_target(is_federated=True))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.send_password_reset(
                request=_request(),
                user_id="target-1",
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400

    async def test_expire_password_federated_400(self):
        storage = _storage_for_returning(_target(is_federated=True))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.expire_user_password(
                request=_request(),
                user_id="target-1",
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400


class TestBulkOperations:
    async def _run(self, operation, user_ids, users, *, scope=None, get_error=None):
        from authglow.models.admin import BulkUserOperation

        storage = MagicMock()
        if get_error is not None:
            storage.get_user = AsyncMock(side_effect=get_error)
        else:
            mapping = {u.id: u for u in users}
            storage.get_user = AsyncMock(side_effect=lambda uid: mapping.get(uid))
        storage.update_user = AsyncMock()
        storage.delete_user = AsyncMock()
        audit = _audit()
        action, event = _recorders()
        with action as action_mock, event as event_mock:
            result = await admin_mod.bulk_user_operation(
                request=_request(),
                operation=BulkUserOperation(user_ids=user_ids, operation=operation, scope=scope),
                current_user=_admin(),
                storage=storage,
                audit_service=audit,
            )
        return result, storage, audit, action_mock, event_mock

    async def test_activate_success(self):
        user = _target(id="u-1", is_active=False)
        result, storage, audit, action, event = await self._run("activate", ["u-1"], [user])
        assert result["success"] == 1
        storage.update_user.assert_awaited_once()
        action.assert_awaited_once()
        event.assert_awaited_once()
        assert audit.log_event.await_count == 1

    async def test_unknown_user_is_counted_as_failure(self):
        result, _, _, _, _ = await self._run("activate", ["ghost"], [])
        assert result["failed"] == 1
        assert "not found" in result["errors"][0]

    async def test_deactivate_federated_is_skipped(self):
        user = _target(id="u-2", is_federated=True, is_active=True)
        result, storage, _, _, _ = await self._run("deactivate", ["u-2"], [user])
        assert result["failed"] == 1
        assert "Federated" in result["errors"][0]
        storage.update_user.assert_not_awaited()

    async def test_assign_scope_appends(self):
        user = _target(id="u-3", scopes=[])
        result, _, audit, action, event = await self._run(
            "assign_scope", ["u-3"], [user], scope="export"
        )
        assert result["success"] == 1
        assert user.scopes == ["export"]
        action.assert_awaited_once()
        event.assert_awaited_once()
        audit.log_event.assert_awaited_once()

    async def test_remove_scope_removes(self):
        user = _target(id="u-4", scopes=["read", "export"])
        result, _, audit, _, _ = await self._run("remove_scope", ["u-4"], [user], scope="export")
        assert result["success"] == 1
        assert user.scopes == ["read"]
        audit.log_event.assert_awaited_once()

    async def test_assign_scope_already_present_is_noop(self):
        user = _target(id="u-8", scopes=["export"])
        result, _, _, _, _ = await self._run("assign_scope", ["u-8"], [user], scope="export")
        assert result["success"] == 1
        assert user.scopes == ["export"]

    async def test_remove_scope_absent_is_noop(self):
        user = _target(id="u-9", scopes=["read"])
        result, _, _, _, _ = await self._run("remove_scope", ["u-9"], [user], scope="export")
        assert result["success"] == 1
        assert user.scopes == ["read"]

    async def test_delete_self_is_rejected(self):
        admin = _admin()
        result, storage, _, _, _ = await self._run("delete", ["admin-1"], [admin])
        assert result["failed"] == 1
        assert "your own account" in result["errors"][0]
        storage.delete_user.assert_not_awaited()

    async def test_delete_federated_is_rejected(self):
        user = _target(id="u-5", is_federated=True)
        result, storage, _, _, _ = await self._run("delete", ["u-5"], [user])
        assert result["failed"] == 1
        storage.delete_user.assert_not_awaited()

    async def test_delete_success(self):
        user = _target(id="u-6")
        result, storage, audit, action, event = await self._run("delete", ["u-6"], [user])
        assert result["success"] == 1
        storage.delete_user.assert_awaited_once()
        action.assert_awaited_once()
        event.assert_awaited_once()
        audit.log_event.assert_awaited_once()

    async def test_internal_error_is_captured(self):
        result, _, _, _, _ = await self._run(
            "activate", ["u-7"], [], get_error=RuntimeError("boom")
        )
        assert result["failed"] == 1
        assert "Error processing" in result["errors"][0]

    async def test_unknown_operation_is_captured(self):
        user = _target(id="u-10")
        result, _, _, _, _ = await self._run("mystery", ["u-10"], [user])
        assert result["failed"] == 1
        assert "Error processing" in result["errors"][0]


class TestRevokeRefreshTokenFailure:
    async def test_revoke_failure_skips_audit(self):
        rt = SimpleNamespace(user_id="u-1", client_id="c-1")
        service = MagicMock()
        service.get_refresh_token_by_id = AsyncMock(return_value=rt)
        service.revoke_token_by_id = AsyncMock(return_value=False)
        audit = _audit()
        with patch.object(admin_mod, "RefreshTokenService", return_value=service):
            out = await admin_mod.revoke_refresh_token_admin(
                token_id="t-1", current_user=_admin(), audit_service=audit
            )
        assert out["message"] == "Token revoked successfully"
        audit.log_event.assert_not_awaited()


class TestExportUserData:
    async def test_export_missing_user_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.export_user_data(user_id="nope", current_user=_admin(), storage=storage)
        assert exc.value.status_code == 404

    async def test_export_aggregates_all_sources(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        consent = SimpleNamespace(
            consent_id="c-1",
            client_id="client-1",
            scopes=["read"],
            granted_at=utcnow(),
            revoked=False,
        )
        rt = SimpleNamespace(
            token_id="t-1",
            client_id="client-1",
            scopes=["read"],
            created_at=utcnow(),
            used_at=None,
            issued_ip="127.0.0.1",
            revoked=False,
        )
        pk = SimpleNamespace(
            credential_id="cred-1",
            name="Laptop",
            device_type="platform",
            created_at=utcnow(),
            last_used_at=None,
        )
        with (
            patch.object(
                LoginHistoryService, "get_login_history", new=AsyncMock(return_value=([], 0))
            ),
            patch.object(
                SecurityEventService,
                "get_security_events",
                new=AsyncMock(return_value=([], 0)),
            ),
            patch.object(
                AdminActionService,
                "get_admin_actions",
                new=AsyncMock(return_value=([], 0)),
            ),
            patch.object(
                RefreshTokenService,
                "list_all_tokens",
                new=AsyncMock(return_value=([rt], 1)),
            ),
            patch.object(PasskeyService, "get_user_passkeys", new=AsyncMock(return_value=[pk])),
            patch.object(
                OAuth2ConsentService,
                "list_user_consents",
                new=AsyncMock(return_value=[consent]),
            ),
            patch.object(OAuth2ClientStorage, "get_client", new=AsyncMock(return_value=None)),
        ):
            out = await admin_mod.export_user_data(
                user_id="target-1", current_user=_admin(), storage=storage
            )
        assert out["user"]["id"] == "target-1"
        assert out["sessions"]["items"][0]["id"] == "t-1"
        assert out["passkeys"][0]["credential_id"] == "cred-1"
        assert out["oauth_consents"][0]["client_name"] == "client-1"
