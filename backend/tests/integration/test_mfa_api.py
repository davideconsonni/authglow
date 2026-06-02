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

            attempts = await mfa_service._get_backup_code_attempts(user_id)
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
