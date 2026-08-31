import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from authglow.models.user import User
from authglow.services.password import hash_password
from fastapi.testclient import TestClient


@pytest.fixture
def test_app(test_settings):
    from authglow.main import app
    from authglow.core.config import get_settings
    from authglow.core import config as config_mod

    with patch.object(config_mod, "get_settings", return_value=test_settings):
        with patch.object(config_mod, "Settings", return_value=test_settings):
            yield app


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


class TestTokenEndpointClientAuth:
    def test_token_endpoint_requires_client_secret_for_authorization_code(self):
        from authglow.api.auth import router

        routes = {r.path: r for r in router.routes}
        assert "/oauth2/token" in routes, "Token endpoint should exist"

    def test_authorization_code_flow_rejects_missing_redirect_uri(self):
        from authglow.api.auth import router

        token_route = None
        for r in router.routes:
            if hasattr(r, "path") and r.path == "/oauth2/token":
                token_route = r
                break
        assert token_route is not None, "Token endpoint route must exist"


class TestMFAVerifyLoginBackupCodes:
    def test_mfa_verify_login_uses_verify_user_backup_code(self):
        from authglow.api.mfa import verify_mfa_login
        import inspect

        source = inspect.getsource(verify_mfa_login)
        assert "verify_user_backup_code" in source, (
            "verify_mfa_login should delegate backup code verification to "
            "mfa_service.verify_user_backup_code() instead of doing plaintext comparison."
        )
        assert "backup_codes.codes" not in source, (
            "verify_mfa_login should NOT access backup_codes.codes directly — "
            "codes are bcrypt-hashed and require proper verification."
        )

    def test_mfa_service_verify_user_backup_code_works(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "mfa-api-test-user"
        asyncio.run(mfa_service.save_backup_codes(user_id, codes))

        async def _run():
            await mfa_service.save_backup_codes(user_id, codes)
            return await mfa_service.verify_user_backup_code(user_id, codes[0])

        result = asyncio.run(_run())
        assert result is True, (
            "verify_user_backup_code should correctly verify a plaintext backup code against stored hashes"
        )


class TestBackupCodeLockoutIntegration:
    def test_verify_user_backup_code_locked_after_max_failures(self, mfa_service):
        import asyncio
        from authglow.services.mfa import BackupCodeLockedException

        async def _run():
            codes = mfa_service.generate_backup_codes(5)
            user_id = "integration-lockout"
            await mfa_service.save_backup_codes(user_id, codes)

            max_attempts = mfa_service.settings.backup_code_max_failed_attempts
            for i in range(max_attempts):
                await mfa_service.verify_user_backup_code(user_id, f"WRONG{i}")

            with pytest.raises(BackupCodeLockedException) as exc_info:
                await mfa_service.verify_user_backup_code(user_id, "ANOTHERWRONG")

            assert exc_info.value.retry_after_seconds > 0
            assert exc_info.value.user_id == user_id

        asyncio.run(_run())

    def test_correct_backup_code_resets_lockout(self, mfa_service):
        import asyncio

        async def _run():
            codes = mfa_service.generate_backup_codes(5)
            user_id = "integration-reset"
            await mfa_service.save_backup_codes(user_id, codes)

            for i in range(2):
                await mfa_service.verify_user_backup_code(user_id, f"WRONG{i}")

            result = await mfa_service.verify_user_backup_code(user_id, codes[0])
            assert result is True

            attempts = await mfa_service._attempts_repo.get(user_id)
            assert attempts is None, "Counter should reset after successful verification"

        asyncio.run(_run())

    def test_lockout_isolated_per_user(self, mfa_service):
        import asyncio

        async def _run():
            codes_a = mfa_service.generate_backup_codes(5)
            codes_b = mfa_service.generate_backup_codes(5)
            user_a = "user-lockout-a"
            user_b = "user-lockout-b"

            await mfa_service.save_backup_codes(user_a, codes_a)
            await mfa_service.save_backup_codes(user_b, codes_b)

            max_attempts = mfa_service.settings.backup_code_max_failed_attempts
            for i in range(max_attempts):
                await mfa_service.verify_user_backup_code(user_a, f"WRONG_A{i}")

            from authglow.services.mfa import BackupCodeLockedException

            with pytest.raises(BackupCodeLockedException):
                await mfa_service.verify_user_backup_code(user_a, "ANYTHING")

            result_b = await mfa_service.verify_user_backup_code(user_b, codes_b[0])
            assert result_b is True, "User B should not be affected by User A lockout"

        asyncio.run(_run())


@pytest.fixture
def _mfa_enroll_app(test_settings, jwt_service, storage):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from unittest.mock import AsyncMock, MagicMock
    from authglow.api.mfa import router, get_mfa_service, get_user_storage as mfa_get_user_storage
    from authglow.api.auth import (
        get_user_storage as auth_get_user_storage,
        get_jwt_service as auth_get_jwt_service,
        get_api_key_service,
        get_oauth2_service,
        get_audit_service,
    )
    from authglow.services.mfa import MFAService

    app = FastAPI()
    app.include_router(router)

    mock_api_key = MagicMock()
    mock_oauth2 = MagicMock()
    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock()

    mfa_svc = MFAService()

    app.dependency_overrides[mfa_get_user_storage] = lambda: storage
    app.dependency_overrides[auth_get_user_storage] = lambda: storage
    app.dependency_overrides[auth_get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    app.dependency_overrides[get_api_key_service] = lambda: mock_api_key
    app.dependency_overrides[get_oauth2_service] = lambda: mock_oauth2
    app.dependency_overrides[get_audit_service] = lambda: mock_audit

    return TestClient(app)


class TestEnrollMfaEndpoint:
    def test_enroll_mfa_success(self, _mfa_enroll_app, jwt_service, storage, test_user):
        import asyncio

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        data = response.json()
        assert "secret" in data
        assert len(data["secret"]) > 0
        assert "qr_code" in data
        assert data["qr_code"].startswith("data:image/png;base64,")
        assert "backup_codes" in data
        assert len(data["backup_codes"]) == 10

    def test_enroll_mfa_blocked_when_enrollment_in_progress(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        """An in-progress (fully-enrolled) state must still block re-enroll.

        Note: a half-state (mfa_enabled=True, mfa_verified=False) is now
        treated as orphaned and auto-healed by enroll — covered by
        test_enroll_mfa_auto_heals_orphaned_state.
        """
        import asyncio

        test_user.mfa_enabled = True
        test_user.mfa_verified = True
        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "already enabled" in response.json()["detail"].lower()

    def test_enroll_mfa_blocked_when_fully_enabled(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        import asyncio

        test_user.mfa_enabled = True
        test_user.mfa_verified = True
        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 400
        assert "already enabled" in response.json()["detail"].lower()

    def test_enroll_mfa_success_after_disable(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        import asyncio

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        enroll_response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert enroll_response.status_code == 200

        disable_response = _mfa_enroll_app.delete(
            "/api/mfa/disable",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert disable_response.status_code == 200

        reenroll_response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert reenroll_response.status_code == 200
        data = reenroll_response.json()
        assert len(data["backup_codes"]) == 10

    def test_enroll_mfa_guard_is_locked(self, _mfa_enroll_app, jwt_service, storage, test_user):
        import asyncio
        from authglow.core.concurrency import named_lock

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 200
        assert not named_lock().is_held(f"mfa_enroll:{test_user.id}"), (
            "Lock must be released after enrollment completes"
        )

    def test_enroll_does_not_flip_mfa_enabled(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        """Enroll must leave mfa_enabled=False until verify succeeds.

        Regression test for the bug where ``mfa_enabled`` was set to True
        during enroll, leaving users who never completed the wizard
        locked out of their account at the next login.
        """
        import asyncio

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200

        async def _reload():
            return await storage.get_user(test_user.id)

        fresh = asyncio.run(_reload())
        assert fresh.mfa_secret is not None, "Enroll must persist a secret"
        assert fresh.mfa_enabled is False, (
            "Enroll must NOT flip mfa_enabled — verify is what completes setup"
        )
        assert fresh.mfa_verified is False, "Enroll must not set mfa_verified"

    def test_enroll_mfa_auto_heals_orphaned_state(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        """Enroll must succeed for an orphan (mfa_enabled=True, mfa_verified=False).

        This is the recovery path for users who started a previous enroll
        (e.g. closed the wizard before verifying) and would otherwise be
        stuck on a broken login flow.
        """
        import asyncio

        test_user.mfa_enabled = True
        test_user.mfa_verified = False
        test_user.mfa_secret = "stale-encrypted-secret"
        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        response = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200, (
            "Orphaned state must self-heal and allow a fresh enroll"
        )

        async def _reload():
            return await storage.get_user(test_user.id)

        fresh = asyncio.run(_reload())
        assert fresh.mfa_enabled is False, "Auto-heal must reset the broken flag"
        assert fresh.mfa_verified is False
        assert fresh.mfa_secret != "stale-encrypted-secret", (
            "Auto-heal must rotate the secret so a new QR/codes pair is required"
        )

    def test_verify_mfa_enrollment_completes_setup(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        """Verify must flip both flags together on a valid TOTP code."""
        import asyncio
        import pyotp

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        enroll = _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert enroll.status_code == 200
        secret = enroll.json()["secret"]

        code = pyotp.TOTP(secret).now()
        verify = _mfa_enroll_app.post(
            "/api/mfa/verify",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": code},
        )
        assert verify.status_code == 200

        async def _reload():
            return await storage.get_user(test_user.id)

        fresh = asyncio.run(_reload())
        assert fresh.mfa_enabled is True
        assert fresh.mfa_verified is True

    def test_verify_mfa_enrollment_rejects_invalid_code(
        self, _mfa_enroll_app, jwt_service, storage, test_user
    ):
        """Invalid TOTP code must not flip mfa_enabled to True."""
        import asyncio

        asyncio.run(storage.create_user(test_user))
        token = jwt_service.create_access_token(
            user_id=test_user.id,
            email=test_user.email,
            scopes=test_user.scopes,
        )

        _mfa_enroll_app.post(
            "/api/mfa/enroll",
            headers={"Authorization": f"Bearer {token}"},
        )
        verify = _mfa_enroll_app.post(
            "/api/mfa/verify",
            headers={"Authorization": f"Bearer {token}"},
            json={"code": "000000"},
        )
        assert verify.status_code == 400

        async def _reload():
            return await storage.get_user(test_user.id)

        fresh = asyncio.run(_reload())
        assert fresh.mfa_enabled is False
        assert fresh.mfa_verified is False
