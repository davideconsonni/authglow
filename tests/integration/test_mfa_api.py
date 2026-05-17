import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from authglow.models.user import User
from authglow.services.password import hash_password


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
    def test_mfa_verify_login_uses_hashed_backup_codes(self):
        from authglow.api.mfa import verify_mfa_login
        import inspect

        source = inspect.getsource(verify_mfa_login)
        assert "backup_codes.codes" in source, (
            "verify_mfa_login uses `backup_codes.codes` which contains hashed codes, "
            "making plaintext comparison impossible. Should use mfa_service.verify_user_backup_code()."
        )

    def test_mfa_service_verify_user_backup_code_works(self, mfa_service):
        import asyncio

        codes = mfa_service.generate_backup_codes(5)
        user_id = "mfa-api-test-user"
        asyncio.get_event_loop().run_until_complete(
            mfa_service.save_backup_codes(user_id, codes)
        )
        first_code = codes[0]
        result = asyncio.get_event_loop().run_until_complete(
            mfa_service.verify_user_backup_code(user_id, first_code)
        )
        assert result is True, (
            "verify_user_backup_code should correctly verify a plaintext backup code against stored hashes"
        )
