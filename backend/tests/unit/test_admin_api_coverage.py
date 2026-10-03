"""Execution tests for ``authglow.api.admin`` (COV-BE-017, slice 1).

Covers the read/listing endpoints, the ``Depends`` factories, the RBAC
authorization helpers, the self-contained ``delete_user_passkey``
mutation and the suspend/unsuspend guard branches. Handlers are called
directly with ``AsyncMock`` collaborators (pattern of
``test_admin_users_update.py``); only the limiter-decorated handler needs
a real Starlette ``Request``.

Slice 2 (bulk operations, data export, password/MFA mutation partials)
is tracked separately as COV-BE-018.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from authglow.api import admin as admin_mod
from authglow.services.admin_action import AdminActionService
from authglow.services.device_auth import DeviceAuthorizationService
from authglow.services.security_event import SecurityEventService


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


class TestAdminDependencyFactories:
    def test_get_user_storage(self):
        with patch.object(admin_mod, "UserStorage", return_value="storage") as ctor:
            assert admin_mod.get_user_storage() == "storage"
            ctor.assert_called_once_with()

    def test_get_audit_service(self):
        with patch.object(admin_mod, "AuditService", return_value="audit") as ctor:
            assert admin_mod.get_audit_service() == "audit"
            ctor.assert_called_once_with()

    def test_get_mfa_service(self):
        with patch.object(admin_mod, "MFAService", return_value="mfa") as ctor:
            assert admin_mod.get_mfa_service() == "mfa"
            ctor.assert_called_once_with()

    def test_get_passkey_service_uses_settings(self):
        settings = SimpleNamespace(
            passkey_rp_id="example.com",
            passkey_rp_name="AuthGlow",
            passkey_origin="https://example.com",
        )
        with (
            patch.object(admin_mod, "get_settings", return_value=settings),
            patch.object(admin_mod, "PasskeyService", return_value="passkey") as ctor,
        ):
            assert admin_mod.get_passkey_service() == "passkey"
            ctor.assert_called_once_with(
                rp_id="example.com",
                rp_name="AuthGlow",
                origin="https://example.com",
            )


class TestAdminAuthorizationHelpers:
    async def test_require_administrator_allows_admin(self):
        rbac = MagicMock()
        rbac.user_has_role = AsyncMock(return_value=True)
        user = _admin()
        with patch.object(admin_mod, "RBACService", return_value=rbac):
            assert await admin_mod.require_administrator(current_user=user) is user

    async def test_require_administrator_rejects_non_admin(self):
        rbac = MagicMock()
        rbac.user_has_role = AsyncMock(return_value=False)
        with patch.object(admin_mod, "RBACService", return_value=rbac):
            with pytest.raises(HTTPException) as exc:
                await admin_mod.require_administrator(current_user=_admin())
        assert exc.value.status_code == 403

    async def test_user_has_admin_role(self):
        rbac = MagicMock()
        rbac.user_has_role = AsyncMock(return_value=True)
        with patch.object(admin_mod, "RBACService", return_value=rbac):
            assert await admin_mod.user_has_admin_role("u-1") is True

    async def test_user_has_permission(self):
        rbac = MagicMock()
        rbac.user_has_permission = AsyncMock(return_value=False)
        with patch.object(admin_mod, "RBACService", return_value=rbac):
            assert await admin_mod.user_has_permission("u-1", "users.manage") is False

    async def test_user_has_any_permission(self):
        rbac = MagicMock()
        rbac.user_has_any_permission = AsyncMock(return_value=True)
        with patch.object(admin_mod, "RBACService", return_value=rbac):
            assert await admin_mod.user_has_any_permission("u-1", ["a", "b"]) is True


class TestDashboardStats:
    async def test_computes_mfa_percentage(self):
        storage = MagicMock()
        storage.get_user_stats = AsyncMock(
            return_value={
                "total": 10,
                "active": 8,
                "inactive": 2,
                "mfa": 4,
                "new_today": 1,
                "new_week": 3,
                "new_month": 5,
            }
        )
        out = await admin_mod.get_dashboard_stats(current_user=_admin(), storage=storage)
        assert out.total_users == 10
        assert out.mfa_percentage == 40.0

    async def test_empty_registry_yields_zero_percentage(self):
        storage = MagicMock()
        storage.get_user_stats = AsyncMock(
            return_value={
                "total": 0,
                "active": 0,
                "inactive": 0,
                "mfa": 0,
                "new_today": 0,
                "new_week": 0,
                "new_month": 0,
            }
        )
        out = await admin_mod.get_dashboard_stats(current_user=_admin(), storage=storage)
        assert out.mfa_percentage == 0


class TestListAndSearchUsers:
    async def test_list_parses_scopes_and_sorts(self):
        storage = MagicMock()
        storage.list_users = AsyncMock(return_value=([_target(id="u-1")], 1))
        out = await admin_mod.list_users_admin(
            search="a",
            is_active=True,
            mfa_enabled=False,
            email_verified=True,
            scopes="read, write ,",
            created_after=None,
            created_before=None,
            last_login_after=None,
            last_login_before=None,
            limit=50,
            offset=0,
            sort="created_at:desc",
            current_user=_admin(),
            storage=storage,
        )
        assert out.total == 1
        assert storage.list_users.call_args.kwargs["scopes"] == ["read", "write"]

    async def test_list_applies_offset_and_limit(self):
        storage = MagicMock()
        users = [_target(id=f"u-{i}") for i in range(3)]
        storage.list_users = AsyncMock(return_value=(users, 3))
        out = await admin_mod.list_users_admin(
            search=None,
            is_active=None,
            mfa_enabled=None,
            email_verified=None,
            scopes=None,
            created_after=None,
            created_before=None,
            last_login_after=None,
            last_login_before=None,
            limit=1,
            offset=1,
            sort=None,
            current_user=_admin(),
            storage=storage,
        )
        assert out.total == 3
        assert len(out.items) == 1

    async def test_list_unknown_sort_field_is_ignored(self):
        storage = MagicMock()
        storage.list_users = AsyncMock(return_value=([_target(id="u-1")], 1))
        out = await admin_mod.list_users_admin(
            search=None,
            is_active=None,
            mfa_enabled=None,
            email_verified=None,
            scopes=None,
            created_after=None,
            created_before=None,
            last_login_after=None,
            last_login_before=None,
            limit=50,
            offset=0,
            sort="email:asc",
            current_user=_admin(),
            storage=storage,
        )
        assert out.total == 1

    async def test_search_returns_page(self):
        storage = MagicMock()
        storage.list_users = AsyncMock(return_value=([_target(id="u-9")], 1))
        out = await admin_mod.search_users(
            search="target",
            is_active=None,
            mfa_enabled=None,
            email_verified=None,
            scopes="read",
            created_after=None,
            created_before=None,
            last_login_after=None,
            last_login_before=None,
            limit=50,
            offset=0,
            current_user=_admin(),
            storage=storage,
        )
        assert out.total == 1
        assert out.items[0].id == "u-9"

    async def test_search_without_scope_filter(self):
        storage = MagicMock()
        storage.list_users = AsyncMock(return_value=([], 0))
        out = await admin_mod.search_users(
            search=None,
            is_active=None,
            mfa_enabled=None,
            email_verified=None,
            scopes=None,
            created_after=None,
            created_before=None,
            last_login_after=None,
            last_login_before=None,
            limit=50,
            offset=0,
            current_user=_admin(),
            storage=storage,
        )
        assert out.total == 0
        assert storage.list_users.call_args.kwargs["scopes"] is None

    async def test_get_user_detail_found(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        out = await admin_mod.get_user_detail(
            user_id="target-1", current_user=_admin(), storage=storage
        )
        assert out.id == "target-1"

    async def test_get_user_detail_missing_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.get_user_detail(user_id="nope", current_user=_admin(), storage=storage)
        assert exc.value.status_code == 404


class TestUserPasskeyReads:
    async def test_passkey_count(self):
        service = MagicMock()
        service.get_user_passkeys = AsyncMock(return_value=[object(), object()])
        out = await admin_mod.get_user_passkey_count(
            user_id="target-1", current_user=_admin(), passkey_service=service
        )
        assert out == {"count": 2}

    async def test_passkey_list(self):
        from authglow.models.passkey import Passkey

        pk = Passkey(
            credential_id="cred-1",
            public_key="pk",
            aaguid="aaguid",
            user_id="target-1",
            name="Laptop",
            device_type="platform",
            transports=["internal"],
        )
        service = MagicMock()
        service.get_user_passkeys = AsyncMock(return_value=[pk])
        out = await admin_mod.get_user_passkeys_list(
            user_id="target-1", current_user=_admin(), passkey_service=service
        )
        assert out[0].credential_id == "cred-1"
        assert out[0].name == "Laptop"


class TestDeleteUserPasskey:
    def _wired(self, *, get_user, delete_result):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=get_user)
        service = MagicMock()
        service.delete_passkey = AsyncMock(return_value=delete_result)
        return storage, service

    async def test_success_records_audit_and_events(self):
        storage, service = self._wired(get_user=_target(), delete_result=True)
        audit = _audit()
        with (
            patch.object(AdminActionService, "record_action", new=AsyncMock()) as action,
            patch.object(SecurityEventService, "record_event", new=AsyncMock()) as event,
        ):
            out = await admin_mod.delete_user_passkey(
                request=_request(),
                user_id="target-1",
                credential_id="cred-1",
                current_user=_admin(),
                passkey_service=service,
                audit_service=audit,
                storage=storage,
            )
        assert out == {"message": "Passkey deleted successfully"}
        audit.log_event.assert_awaited_once()
        action.assert_awaited_once()
        event.assert_awaited_once()

    async def test_missing_user_404(self):
        storage, service = self._wired(get_user=None, delete_result=True)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.delete_user_passkey(
                request=_request(),
                user_id="nope",
                credential_id="cred-1",
                current_user=_admin(),
                passkey_service=service,
                audit_service=_audit(),
                storage=storage,
            )
        assert exc.value.status_code == 404

    async def test_missing_passkey_404(self):
        storage, service = self._wired(get_user=_target(), delete_result=False)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.delete_user_passkey(
                request=_request(),
                user_id="target-1",
                credential_id="missing",
                current_user=_admin(),
                passkey_service=service,
                audit_service=_audit(),
                storage=storage,
            )
        assert exc.value.status_code == 404


class TestSessionsAndConsents:
    async def test_cleanup_expired_sessions(self):
        service = MagicMock()
        service.cleanup_expired_tokens = AsyncMock(return_value=7)
        with patch.object(admin_mod, "RefreshTokenService", return_value=service):
            out = await admin_mod.cleanup_expired_sessions(current_user=_admin())
        assert out == {"deleted": 7, "message": "Cleaned up 7 expired tokens"}

    async def test_list_oauth_consents(self):
        service = MagicMock()
        service.list_all_for_admin = AsyncMock(return_value=(["consent"], 1))
        with patch.object(admin_mod, "OAuth2ConsentService", return_value=service):
            out = await admin_mod.get_oauth_consents_admin(
                email="a@b.c", limit=50, offset=0, current_user=_admin()
            )
        assert out.total == 1

    async def test_revoke_consent_success(self):
        service = MagicMock()
        service.revoke_consent = AsyncMock(return_value=True)
        audit = _audit()
        with patch.object(admin_mod, "OAuth2ConsentService", return_value=service):
            out = await admin_mod.revoke_consent_admin(
                consent_id="consent-1", current_user=_admin(), audit_service=audit
            )
        assert out == {"message": "Consent revoked successfully"}
        audit.log_event.assert_awaited_once()

    async def test_revoke_consent_404(self):
        service = MagicMock()
        service.revoke_consent = AsyncMock(return_value=False)
        with patch.object(admin_mod, "OAuth2ConsentService", return_value=service):
            with pytest.raises(HTTPException) as exc:
                await admin_mod.revoke_consent_admin(
                    consent_id="missing", current_user=_admin(), audit_service=_audit()
                )
        assert exc.value.status_code == 404

    async def test_list_admin_actions(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target())
        with patch.object(
            AdminActionService,
            "get_admin_actions",
            new=AsyncMock(return_value=(["action"], 1)),
        ):
            out = await admin_mod.get_user_admin_actions(
                user_id="target-1",
                limit=50,
                offset=0,
                current_user=_admin(),
                storage=storage,
            )
        assert out.total == 1

    async def test_list_admin_actions_missing_user_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.get_user_admin_actions(
                user_id="nope",
                limit=50,
                offset=0,
                current_user=_admin(),
                storage=storage,
            )
        assert exc.value.status_code == 404


class TestSuspendUnsuspendGuards:
    async def test_suspend_missing_user_404(self):
        from authglow.models.admin import SuspendRequest

        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.suspend_user(
                user_id="nope",
                body=SuspendRequest(duration_hours=1),
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 404

    async def test_unsuspend_missing_user_404(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            await admin_mod.unsuspend_user(
                user_id="nope", current_user=_admin(), storage=storage, audit_service=_audit()
            )
        assert exc.value.status_code == 404

    async def test_unsuspend_not_suspended_400(self):
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_target(suspended_until=None))
        with pytest.raises(HTTPException) as exc:
            await admin_mod.unsuspend_user(
                user_id="target-1",
                current_user=_admin(),
                storage=storage,
                audit_service=_audit(),
            )
        assert exc.value.status_code == 400


class TestJwkKeys:
    def _jwt_service(self):
        service = MagicMock()
        service.get_keyring_info = MagicMock(
            return_value={
                "active_kid": "k2",
                "keys": {
                    "k1": {
                        "status": "retired",
                        "created_at": "2026-01-01",
                        "algorithm": "RS256",
                        "key_size": 2048,
                    },
                    "k2": {
                        "status": "active",
                        "created_at": "2026-02-01",
                        "algorithm": "RS256",
                        "key_size": 2048,
                    },
                    "k3": {
                        "status": "retired",
                        "created_at": "2025-12-01",
                        "algorithm": "RS256",
                        "key_size": 2048,
                    },
                },
            }
        )
        return service

    async def test_lists_keys_sorted_with_size_fallbacks(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        valid_pem = private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        keystore = MagicMock()
        keystore.read_public_key = AsyncMock(
            side_effect=lambda kid: {"k1": valid_pem, "k2": b"not-a-pem"}.get(kid)
        )
        with (
            patch.object(
                admin_mod, "get_jwt_service", new=AsyncMock(return_value=self._jwt_service())
            ),
            patch(
                "authglow.repositories.dependencies.get_keystore_repository",
                return_value=keystore,
            ),
        ):
            out = await admin_mod.get_jwk_keys(current_user=_admin())

        assert out["active_kid"] == "k2"
        assert [k["kid"] for k in out["keys"]] == ["k2", "k1", "k3"]
        by_kid = {k["kid"]: k for k in out["keys"]}
        assert by_kid["k1"]["key_size"] == 2048
        assert by_kid["k1"]["file_exists"] is True
        assert by_kid["k2"]["key_size"] == 2048  # invalid PEM -> meta fallback
        assert by_kid["k2"]["is_active"] is True
        assert by_kid["k3"]["file_exists"] is False


class TestDeviceAuthorizations:
    def _auth(self):
        from authglow.core.datetime import utcnow

        return SimpleNamespace(
            device_code="dev-1",
            user_code="USER-1",
            client_id="client-1",
            scope="read",
            status="pending",
            user_id=None,
            created_at=utcnow(),
            expires_at=utcnow(),
            authorized_at=None,
        )

    async def test_list_device_authorizations(self):
        with patch.object(
            DeviceAuthorizationService, "list_all", new=AsyncMock(return_value=[self._auth()])
        ):
            out = await admin_mod.list_device_authorizations(
                status="pending", current_user=_admin()
            )
        assert out["total"] == 1
        assert out["device_authorizations"][0]["device_code"] == "dev-1"
        assert out["device_authorizations"][0]["authorized_at"] is None

    async def test_revoke_success(self):
        audit = _audit()
        with patch.object(DeviceAuthorizationService, "revoke", new=AsyncMock(return_value=True)):
            out = await admin_mod.revoke_device_authorization(
                device_code="dev-1",
                request=_request(),
                current_user=_admin(),
                audit_service=audit,
            )
        assert out == {"message": "Device authorization revoked"}
        audit.log_event.assert_awaited_once()

    async def test_revoke_missing_404(self):
        with patch.object(DeviceAuthorizationService, "revoke", new=AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                await admin_mod.revoke_device_authorization(
                    device_code="missing",
                    request=_request(),
                    current_user=_admin(),
                    audit_service=_audit(),
                )
        assert exc.value.status_code == 404
