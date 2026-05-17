import pytest
from authglow.models.user import User
from authglow.services.password import hash_password


class TestAuthAPIEndpointStructure:
    def test_auth_router_has_key_endpoints(self):
        from authglow.api.auth import router

        paths = set()
        for r in router.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
            elif hasattr(r, "routes"):
                for sr in r.routes:
                    if hasattr(sr, "path"):
                        paths.add(sr.path)
        assert "/oauth2/token" in paths
        assert "/api/token" in paths
        assert "/oauth2/authorize" in paths
        assert "/api/token/api-key" in paths

    def test_token_endpoint_code_references_authorization_code(self):
        from authglow.api.auth import token_endpoint
        import inspect

        source = inspect.getsource(token_endpoint)
        assert "authorization_code" in source
        assert "client_credentials" in source
        assert "refresh_token" in source


class TestLoginLockoutOrder:
    def test_login_checks_account_lockout_after_password(self):
        from authglow.api.auth import login_for_access_token
        import inspect

        source = inspect.getsource(login_for_access_token)
        verify_pwd_pos = source.find("verify_password")
        lockout_pos = source.find("is_account_locked")
        assert verify_pwd_pos < lockout_pos, (
            "Bug: Account lockout should be checked BEFORE password verification "
            "to prevent timing attacks. Currently, lockout is checked after."
        )
