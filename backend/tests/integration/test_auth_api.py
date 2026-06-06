import pytest
import base64
from unittest.mock import AsyncMock, MagicMock, patch
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
        assert "/api/oauth2/authorize" in paths
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


class TestExtractBasicAuth:
    def test_extract_from_valid_basic_auth(self):
        from authglow.api.auth import _extract_basic_auth

        creds = base64.b64encode(b"myclientid:myclientsecret").decode()
        request = MagicMock()
        request.headers.get.return_value = f"Basic {creds}"
        cid, csec = _extract_basic_auth(request)
        assert cid == "myclientid"
        assert csec == "myclientsecret"

    def test_extract_from_basic_auth_with_colon_in_secret(self):
        from authglow.api.auth import _extract_basic_auth

        creds = base64.b64encode(b"myclientid:secret:with:colons").decode()
        request = MagicMock()
        request.headers.get.return_value = f"Basic {creds}"
        cid, csec = _extract_basic_auth(request)
        assert cid == "myclientid"
        assert csec == "secret:with:colons"

    def test_returns_none_for_missing_header(self):
        from authglow.api.auth import _extract_basic_auth

        request = MagicMock()
        request.headers.get.return_value = ""
        cid, csec = _extract_basic_auth(request)
        assert cid is None
        assert csec is None

    def test_returns_none_for_bearer_token_header(self):
        from authglow.api.auth import _extract_basic_auth

        request = MagicMock()
        request.headers.get.return_value = "Bearer sometoken"
        cid, csec = _extract_basic_auth(request)
        assert cid is None
        assert csec is None

    def test_returns_none_for_malformed_basic_auth(self):
        from authglow.api.auth import _extract_basic_auth

        creds = base64.b64encode(b"nocolonhere").decode()
        request = MagicMock()
        request.headers.get.return_value = f"Basic {creds}"
        cid, csec = _extract_basic_auth(request)
        assert cid is None
        assert csec is None

    def test_returns_none_for_invalid_base64(self):
        from authglow.api.auth import _extract_basic_auth

        request = MagicMock()
        request.headers.get.return_value = "Basic !!!invalid!!!"
        cid, csec = _extract_basic_auth(request)
        assert cid is None
        assert csec is None


class TestTokenEndpointClientAuth:
    """Tests for C4: Token endpoint must authenticate the client during
    authorization_code exchange (RFC 6749 Section 4.1.3)."""

    def _make_auth_code(self, client_id="test-client-id", user_id="user-1"):
        from authglow.models.token import AuthorizationCode
        from datetime import timedelta
        from authglow.core.datetime import utcnow

        return AuthorizationCode(
            client_id=client_id,
            user_id=user_id,
            redirect_uri="http://localhost:8000/callback",
            scope="read",
            expires_at=utcnow() + timedelta(minutes=10),
        )

    @pytest.mark.asyncio
    async def test_confidential_client_requires_secret(self, oauth2_service):
        """C4: Confidential client MUST provide client_secret."""
        from authglow.api.auth import token_endpoint
        from fastapi import HTTPException
        from starlette.datastructures import Headers

        auth_code = self._make_auth_code()
        auth_code_used = auth_code.model_copy(update={"used": False})

        mock_request = MagicMock()
        mock_request.headers = Headers({})
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_storage = AsyncMock()
        mock_jwt = MagicMock()
        mock_rt_service = AsyncMock()

        mock_client = MagicMock()
        mock_client.is_confidential = True
        mock_client.is_active = True
        oauth2_service.client_storage = MagicMock()
        oauth2_service.client_storage.get_client = AsyncMock(return_value=mock_client)
        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_used)
        oauth2_service.verify_client = AsyncMock(return_value=True)

        with pytest.raises(HTTPException) as exc_info:
            await token_endpoint(
                request=mock_request,
                response=MagicMock(),
                grant_type="authorization_code",
                code=auth_code.code,
                redirect_uri=auth_code.redirect_uri,
                client_id=auth_code.client_id,
                client_secret=None,
                refresh_token=None,
                scope=None,
                code_verifier=None,
                storage=mock_storage,
                jwt_service=mock_jwt,
                oauth2_service=oauth2_service,
                refresh_token_service=mock_rt_service,
            )
        assert exc_info.value.status_code == 401
        assert "client authentication required" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_confidential_client_wrong_secret_rejected(self, oauth2_service):
        """C4: Confidential client with wrong secret must be rejected."""
        from authglow.api.auth import token_endpoint
        from fastapi import HTTPException
        from starlette.datastructures import Headers

        auth_code = self._make_auth_code()
        auth_code_used = auth_code.model_copy(update={"used": False})

        mock_request = MagicMock()
        mock_request.headers = Headers({})
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_storage = AsyncMock()
        mock_jwt = MagicMock()
        mock_rt_service = AsyncMock()

        mock_client = MagicMock()
        mock_client.is_confidential = True
        mock_client.is_active = True
        oauth2_service.client_storage = MagicMock()
        oauth2_service.client_storage.get_client = AsyncMock(return_value=mock_client)
        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_used)
        oauth2_service.verify_client = AsyncMock(return_value=False)

        with pytest.raises(HTTPException) as exc_info:
            await token_endpoint(
                request=mock_request,
                response=MagicMock(),
                grant_type="authorization_code",
                code=auth_code.code,
                redirect_uri=auth_code.redirect_uri,
                client_id=auth_code.client_id,
                client_secret="wrong-secret",
                refresh_token=None,
                scope=None,
                code_verifier=None,
                storage=mock_storage,
                jwt_service=mock_jwt,
                oauth2_service=oauth2_service,
                refresh_token_service=mock_rt_service,
            )
        assert exc_info.value.status_code == 401
        assert "invalid client credentials" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_client_id_mismatch_rejected(self, oauth2_service):
        """C4: client_id must match the authorization code's client_id."""
        from authglow.api.auth import token_endpoint
        from fastapi import HTTPException
        from starlette.datastructures import Headers

        auth_code = self._make_auth_code(client_id="correct-client")
        auth_code_used = auth_code.model_copy(update={"used": False})

        mock_request = MagicMock()
        mock_request.headers = Headers({})
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_storage = AsyncMock()
        mock_jwt = MagicMock()
        mock_rt_service = AsyncMock()

        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_used)

        with pytest.raises(HTTPException) as exc_info:
            await token_endpoint(
                request=mock_request,
                response=MagicMock(),
                grant_type="authorization_code",
                code=auth_code.code,
                redirect_uri=auth_code.redirect_uri,
                client_id="different-client",
                client_secret="secret",
                refresh_token=None,
                scope=None,
                code_verifier=None,
                storage=mock_storage,
                jwt_service=mock_jwt,
                oauth2_service=oauth2_service,
                refresh_token_service=mock_rt_service,
            )
        assert exc_info.value.status_code == 400
        assert "mismatch" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_missing_client_id_rejected(self, oauth2_service):
        """C4: Missing client_id must be rejected."""
        from authglow.api.auth import token_endpoint
        from fastapi import HTTPException
        from starlette.datastructures import Headers

        auth_code = self._make_auth_code()
        auth_code_used = auth_code.model_copy(update={"used": False})

        mock_request = MagicMock()
        mock_request.headers = Headers({})
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_used)

        mock_storage = AsyncMock()
        mock_jwt = MagicMock()
        mock_rt_service = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            await token_endpoint(
                request=mock_request,
                response=MagicMock(),
                grant_type="authorization_code",
                code=auth_code.code,
                redirect_uri=auth_code.redirect_uri,
                client_id=None,
                client_secret=None,
                refresh_token=None,
                scope=None,
                code_verifier=None,
                storage=mock_storage,
                jwt_service=mock_jwt,
                oauth2_service=oauth2_service,
                refresh_token_service=mock_rt_service,
            )
        assert exc_info.value.status_code == 400
        assert "missing client_id" in exc_info.value.detail.lower()

    @pytest.mark.asyncio
    async def test_public_client_without_pkce_rejected(self, oauth2_service):
        """C4: Public clients without PKCE must be rejected."""
        from authglow.api.auth import token_endpoint
        from fastapi import HTTPException
        from starlette.datastructures import Headers

        auth_code = self._make_auth_code()
        auth_code_no_pkce = auth_code.model_copy(
            update={
                "used": False,
                "code_challenge": None,
                "code_challenge_method": None,
            }
        )

        mock_request = MagicMock()
        mock_request.headers = Headers({})
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_storage = AsyncMock()
        mock_jwt = MagicMock()
        mock_rt_service = AsyncMock()

        mock_client = MagicMock()
        mock_client.is_confidential = False
        mock_client.is_active = True
        oauth2_service.client_storage = MagicMock()
        oauth2_service.client_storage.get_client = AsyncMock(return_value=mock_client)
        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_no_pkce)
        oauth2_service.verify_client = AsyncMock(return_value=True)

        with pytest.raises(HTTPException) as exc_info:
            await token_endpoint(
                request=mock_request,
                response=MagicMock(),
                grant_type="authorization_code",
                code=auth_code.code,
                redirect_uri=auth_code.redirect_uri,
                client_id=auth_code.client_id,
                client_secret=None,
                refresh_token=None,
                scope=None,
                code_verifier=None,
                storage=mock_storage,
                jwt_service=mock_jwt,
                oauth2_service=oauth2_service,
                refresh_token_service=mock_rt_service,
            )
        assert exc_info.value.status_code == 400
        assert "PKCE" in exc_info.value.detail or "code_challenge" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_basic_auth_credentials_extracted(self, oauth2_service):
        """C4: Client credentials from HTTP Basic Auth should be accepted."""
        from authglow.api.auth import token_endpoint
        from starlette.datastructures import Headers
        import hashlib

        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("=")

        auth_code = self._make_auth_code()
        auth_code_pkce = auth_code.model_copy(
            update={
                "used": False,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )

        creds = base64.b64encode(b"test-client-id:test-client-secret").decode()
        headers = Headers({"Authorization": f"Basic {creds}"})

        mock_request = MagicMock()
        mock_request.headers = headers
        mock_request.client = MagicMock()
        mock_request.client.host = "127.0.0.1"

        mock_user = User(
            id="user-1",
            email="user@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            scopes=["read"],
        )

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=mock_user)
        mock_jwt = MagicMock()
        mock_jwt.create_token_response = MagicMock(return_value=MagicMock())
        mock_rt_service = AsyncMock()
        mock_rt = MagicMock()
        mock_rt.token = "rt-token"
        mock_rt.scopes = ["read"]
        mock_rt_service.create_refresh_token = AsyncMock(return_value=mock_rt)

        mock_client = MagicMock()
        mock_client.is_confidential = True
        mock_client.is_active = True
        oauth2_service.client_storage = MagicMock()
        oauth2_service.client_storage.get_client = AsyncMock(return_value=mock_client)
        oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code_pkce)
        oauth2_service.mark_code_as_used = AsyncMock(return_value=True)
        oauth2_service.verify_client = AsyncMock(return_value=True)
        oauth2_service.process_scopes = AsyncMock(return_value=["read"])

        result = await token_endpoint(
            request=mock_request,
            response=MagicMock(),
            grant_type="authorization_code",
            code=auth_code_pkce.code,
            redirect_uri=auth_code_pkce.redirect_uri,
            client_id=None,
            client_secret=None,
            refresh_token=None,
            scope=None,
            code_verifier=code_verifier,
            storage=mock_storage,
            jwt_service=mock_jwt,
            oauth2_service=oauth2_service,
            refresh_token_service=mock_rt_service,
        )

        oauth2_service.verify_client.assert_called_once_with("test-client-id", "test-client-secret")


class TestInviteUserSetPasswordLink:
    @pytest.fixture
    def _invite_app(self, test_settings, jwt_service):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from authglow.api.auth import router, get_user_storage
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app = FastAPI()
        app.include_router(router)

        admin_user = User(
            id="admin-inviter",
            email="admin@test.com",
            hashed_password=hash_password("AdminP@ss123!"),
            is_active=True,
            scopes=["read", "write", "admin"],
            email_verified=True,
        )

        mock_storage = MagicMock()
        mock_storage.get_user = AsyncMock(return_value=admin_user)
        mock_storage.get_user_by_email = AsyncMock(return_value=None)
        mock_storage.create_user = AsyncMock(side_effect=lambda user: user)

        mock_audit = MagicMock()
        mock_audit.log_event = AsyncMock()

        mock_api_key = MagicMock()
        mock_oauth2 = MagicMock()

        from authglow.api.auth import (
            get_api_key_service,
            get_oauth2_service,
            get_audit_service,
        )

        app.dependency_overrides[get_user_storage] = lambda: mock_storage
        app.dependency_overrides[get_api_key_service] = lambda: mock_api_key
        app.dependency_overrides[get_oauth2_service] = lambda: mock_oauth2
        app.dependency_overrides[get_audit_service] = lambda: mock_audit

        client = TestClient(app)
        client._mock_storage = mock_storage
        return client

    def test_invite_user_sends_set_password_link_not_temp_password(
        self, _invite_app, test_settings, jwt_service
    ):
        from unittest.mock import AsyncMock, MagicMock, patch
        from authglow.models.user import User
        from authglow.services.password import hash_password

        invited_user = User(
            id="invited-user-001",
            email="invited@test.com",
            hashed_password=hash_password("placeholder"),
            first_name="Invited",
            last_name="User",
            is_active=True,
            scopes=["read"],
            is_invited=True,
            email_verified=False,
        )

        mock_storage = MagicMock()
        mock_storage.get_user = AsyncMock(return_value=invited_user)
        mock_storage.get_user_by_email = AsyncMock(return_value=None)
        mock_storage.create_user = AsyncMock(return_value=invited_user)

        from authglow.services.email_verification import EmailVerificationService

        mock_verification = MagicMock()
        mock_verification.create_verification_token = AsyncMock(
            return_value=MagicMock(token="verify-token-abc")
        )

        captured_context = {}

        async def capture_send_template(**kwargs):
            for k, v in kwargs.get("context", {}).items():
                captured_context[k] = v

        mock_email = MagicMock()
        mock_email.send_template = AsyncMock(side_effect=capture_send_template)

        admin_user = User(
            id="admin-inviter",
            email="admin@test.com",
            hashed_password=hash_password("AdminP@ss123!"),
            is_active=True,
            scopes=["read", "write", "admin"],
            email_verified=True,
        )

        token = jwt_service.create_access_token(
            user_id=admin_user.id,
            email=admin_user.email,
            scopes=admin_user.scopes,
        )

        with (
            patch(
                "authglow.api.auth.EmailVerificationService",
                return_value=mock_verification,
            ),
            patch(
                "authglow.api.auth.get_email_service",
                return_value=mock_email,
            ),
            patch(
                "authglow.api.auth.get_user_storage",
                return_value=mock_storage,
            ),
        ):
            response = _invite_app.post(
                "/api/users/invite",
                json={
                    "email": "invited@test.com",
                    "first_name": "Invited",
                    "last_name": "User",
                    "scopes": ["read"],
                },
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 201
        assert "set_password_url" in captured_context, (
            "invite_user must include set_password_url in email context"
        )
        assert "temp_password" not in captured_context, (
            "invite_user must NOT include temp_password in email context"
        )
        assert "token=" in captured_context.get("set_password_url", ""), (
            "set_password_url must contain a reset token"
        )

    def test_invited_user_gets_password_reset_token(self, _invite_app, test_settings, jwt_service):
        from unittest.mock import AsyncMock, MagicMock, patch
        from uuid import uuid4

        user_id = str(uuid4())
        email_addr = "invited-flow@test.com"

        from authglow.models.user import User
        from authglow.services.password import hash_password

        invited_user = User(
            id=user_id,
            email=email_addr,
            hashed_password=hash_password("placeholder"),
            first_name="Flow",
            last_name="Test",
            is_active=True,
            scopes=["read"],
            is_invited=True,
            email_verified=True,
        )

        admin_user = User(
            id="admin-inviter",
            email="admin@test.com",
            hashed_password=hash_password("AdminP@ss123!"),
            is_active=True,
            scopes=["read", "write", "admin"],
            email_verified=True,
        )

        async def _mock_get_user(uid):
            if uid == admin_user.id:
                return admin_user
            if uid == user_id:
                return invited_user
            return None

        _invite_app._mock_storage.get_user = AsyncMock(side_effect=_mock_get_user)
        _invite_app._mock_storage.create_user = AsyncMock(return_value=invited_user)

        from authglow.services.email_verification import EmailVerificationService

        mock_verification = MagicMock()
        mock_verification.create_verification_token = AsyncMock(
            return_value=MagicMock(token="verify-token-flow")
        )

        captured_set_password_url = {}

        async def capture_send_template(**kwargs):
            ctx = kwargs.get("context", {})
            captured_set_password_url["url"] = ctx.get("set_password_url", "")

        mock_email = MagicMock()
        mock_email.send_template = AsyncMock(side_effect=capture_send_template)

        from authglow.models.password_reset import PasswordResetToken
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        mock_reset_plaintext = "reset-plaintext-token-for-test"
        mock_reset_token = PasswordResetToken(
            token_lookup="test-reset-lookup",
            user_id=user_id,
            email=email_addr,
            token_hash="$2b$12$hashplaceholder...",
            expires_at=utcnow() + timedelta(minutes=1440),
        )

        mock_reset_service = MagicMock()
        mock_reset_service.create_reset_token = AsyncMock(
            return_value=(mock_reset_token, mock_reset_plaintext)
        )

        admin_token = jwt_service.create_access_token(
            user_id=admin_user.id,
            email=admin_user.email,
            scopes=admin_user.scopes,
        )

        with (
            patch(
                "authglow.api.auth.EmailVerificationService",
                return_value=mock_verification,
            ),
            patch(
                "authglow.api.auth.get_email_service",
                return_value=mock_email,
            ),
            patch(
                "authglow.api.auth.PasswordResetService",
                return_value=mock_reset_service,
            ),
        ):
            response = _invite_app.post(
                "/api/users/invite",
                json={
                    "email": email_addr,
                    "first_name": "Flow",
                    "last_name": "Test",
                    "scopes": ["read"],
                },
                headers={"Authorization": f"Bearer {admin_token}"},
            )

        assert response.status_code == 201

        set_password_url = captured_set_password_url.get("url", "")
        assert f"token={mock_reset_plaintext}" in set_password_url, (
            "set_password_url must contain the reset plaintext token"
        )

        mock_reset_service.create_reset_token.assert_awaited_once_with(
            user_id=user_id,
            email=email_addr,
            expires_in_minutes=1440,
        )

    def test_invite_user_requires_admin_scope(self, _invite_app, jwt_service):
        from unittest.mock import AsyncMock, MagicMock
        from authglow.models.user import User
        from authglow.services.password import hash_password

        non_admin = User(
            id="regular-user",
            email="user@test.com",
            hashed_password=hash_password("UserP@ss123!"),
            is_active=True,
            scopes=["read"],
            email_verified=True,
        )

        token = jwt_service.create_access_token(
            user_id=non_admin.id,
            email=non_admin.email,
            scopes=non_admin.scopes,
        )

        response = _invite_app.post(
            "/api/users/invite",
            json={
                "email": "invited@test.com",
                "first_name": "Test",
                "last_name": "User",
                "scopes": ["read"],
            },
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403


class TestVerificationEmailNoTokenInUrl:
    def test_send_verification_email_sends_code_not_url(self, test_settings):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from authglow.models.user import User
        from authglow.services.password import hash_password
        from authglow.services.email_verification import EmailVerificationService

        user = User(
            id="verify-email-user",
            email="verify@test.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            email_verified=False,
            scopes=["read"],
        )

        captured_context = {}

        async def capture_send_template(**kwargs):
            ctx = kwargs.get("context", {})
            for k, v in ctx.items():
                captured_context[k] = v
            return MagicMock(success=True)

        mock_email = MagicMock()
        mock_email.send_template = AsyncMock(side_effect=capture_send_template)

        async def _run():
            with patch(
                "authglow.services.email_verification.get_email_service",
                return_value=mock_email,
            ):
                svc = EmailVerificationService()
                result = await svc.send_verification_email(user, "test-verification-token")
            return result

        result = asyncio.run(_run())

        assert result is True

        assert "verification_code" in captured_context, (
            "send_verification_email must include verification_code"
        )
        assert captured_context["verification_code"] == "test-verification-token", (
            "verification_code must be the plaintext token"
        )
        assert "verification_url" not in captured_context, (
            "send_verification_email must NOT include verification_url with token"
        )
        assert "verify_page_url" in captured_context, (
            "send_verification_email must include verify_page_url"
        )
        assert "token=" not in captured_context.get("verify_page_url", ""), (
            "verify_page_url must NOT contain the token"
        )
