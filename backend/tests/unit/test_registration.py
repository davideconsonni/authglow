import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from starlette.requests import Request
from starlette.datastructures import Headers, QueryParams
from authglow.models.user import RegisterUser


def make_request(method="POST", client_host="127.0.0.1"):
    scope = {
        "type": "http",
        "method": method,
        "path": "/api/users",
        "query_string": b"",
        "headers": [],
        "client": (client_host, 12345),
    }
    return Request(scope)


class TestRegisterUserModel:
    def test_register_user_valid(self):
        user = RegisterUser(
            email="test@example.com",
            password="SecurePass1!",
            first_name="Test",
            last_name="User",
        )
        assert user.email == "test@example.com"
        assert user.password == "SecurePass1!"
        assert user.first_name == "Test"
        assert user.last_name == "User"

    def test_register_user_minimal(self):
        user = RegisterUser(
            email="test@example.com",
            password="SecurePass1!",
        )
        assert user.first_name is None
        assert user.last_name is None

    def test_register_user_password_too_short(self):
        with pytest.raises(Exception):
            RegisterUser(email="test@example.com", password="short")


class TestRegisterEndpointExists:
    def test_register_route_in_router(self):
        from authglow.api.auth import router

        register_methods = set()
        for r in router.routes:
            if hasattr(r, "path") and hasattr(r, "methods") and r.path == "/api/users":
                for m in r.methods:
                    register_methods.add(m)

        assert "POST" in register_methods, "POST /api/users route must exist"
        assert "GET" in register_methods, "GET /api/users route must still exist"


class TestRegisterEndpointLogic:
    @pytest.fixture(autouse=True)
    def setup_mocks(self):
        self.mock_storage = AsyncMock()
        self.mock_audit = AsyncMock()
        self.mock_validator = MagicMock()
        self.mock_settings = MagicMock()
        self.mock_settings.allow_public_registration = True
        self.mock_settings.base_url = "http://localhost:8001"
        self.mock_settings.company_name = "AuthGlow"

    @pytest.mark.asyncio
    async def test_register_disabled_setting(self):
        from authglow.api.auth import register_user
        from fastapi import HTTPException

        self.mock_settings.allow_public_registration = False
        self.mock_validator.validate.return_value = (True, [])

        request = make_request()

        user_data = RegisterUser(
            email="test@example.com",
            password="SecurePass1!",
        )

        with (
            patch("authglow.api.auth.get_settings", return_value=self.mock_settings),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await register_user(
                    request=request,
                    user_data=user_data,
                    storage=self.mock_storage,
                    password_validator=self.mock_validator,
                    audit_service=self.mock_audit,
                )
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self):
        from authglow.api.auth import register_user
        from fastapi import HTTPException

        self.mock_validator.validate.return_value = (True, [])

        existing_user = MagicMock()
        self.mock_storage.get_user_by_email.return_value = existing_user

        request = make_request()

        user_data = RegisterUser(
            email="existing@example.com",
            password="SecurePass1!",
        )

        with (
            patch("authglow.api.auth.get_settings", return_value=self.mock_settings),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await register_user(
                    request=request,
                    user_data=user_data,
                    storage=self.mock_storage,
                    password_validator=self.mock_validator,
                    audit_service=self.mock_audit,
                )
            assert exc_info.value.status_code == 400
            assert "already exists" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_register_weak_password(self):
        from authglow.api.auth import register_user
        from fastapi import HTTPException

        self.mock_validator.validate.return_value = (
            False,
            ["Password must be at least 8 characters"],
        )

        request = make_request()

        user_data = RegisterUser(
            email="test@example.com",
            password="SecurePass1!",
        )

        with (
            patch("authglow.api.auth.get_settings", return_value=self.mock_settings),
        ):
            with pytest.raises(HTTPException) as exc_info:
                await register_user(
                    request=request,
                    user_data=user_data,
                    storage=self.mock_storage,
                    password_validator=self.mock_validator,
                    audit_service=self.mock_audit,
                )
            assert exc_info.value.status_code == 400
            assert "Password validation failed" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_register_creates_user_with_correct_defaults(self):
        from authglow.api.auth import register_user
        from authglow.models.user import User

        self.mock_validator.validate.return_value = (True, [])
        self.mock_storage.get_user_by_email.return_value = None

        created_user = User(
            id="user-123",
            email="new@example.com",
            hashed_password="$2b$12$fakehash",
            scopes=["read"],
            is_active=True,
            is_invited=False,
            email_verified=False,
        )
        self.mock_storage.create_user.return_value = created_user

        request = make_request()

        user_data = RegisterUser(
            email="new@example.com",
            password="SecurePass1!",
            first_name="New",
            last_name="User",
        )

        with (
            patch("authglow.api.auth.get_settings", return_value=self.mock_settings),
            patch("authglow.api.auth.EmailVerificationService") as mock_ev_cls,
            patch("authglow.api.auth.get_email_service") as mock_email_factory,
        ):
            mock_ev = AsyncMock()
            mock_ev.create_verification_token.return_value = MagicMock(
                verification_code="ABCD-EFGH-JKMN"
            )
            mock_ev_cls.return_value = mock_ev
            mock_email_svc = AsyncMock()
            mock_email_factory.return_value = mock_email_svc

            result = await register_user(
                request=request,
                user_data=user_data,
                storage=self.mock_storage,
                password_validator=self.mock_validator,
                audit_service=self.mock_audit,
            )

            call_args = self.mock_storage.create_user.call_args[0][0]
            assert call_args.email == "new@example.com"
            assert call_args.is_invited is False
            assert call_args.email_verified is False
            assert call_args.scopes == ["read"]
            assert call_args.is_active is True
            assert call_args.first_name == "New"
            assert call_args.last_name == "User"

            assert result.email == "new@example.com"

    @pytest.mark.asyncio
    async def test_register_logs_audit_event(self):
        from authglow.api.auth import register_user
        from authglow.models.user import User

        self.mock_validator.validate.return_value = (True, [])
        self.mock_storage.get_user_by_email.return_value = None

        created_user = User(
            id="user-123",
            email="audit@example.com",
            hashed_password="$2b$12$fakehash",
            scopes=["read"],
            is_active=True,
            is_invited=False,
            email_verified=False,
        )
        self.mock_storage.create_user.return_value = created_user

        request = make_request()

        user_data = RegisterUser(
            email="audit@example.com",
            password="SecurePass1!",
        )

        with (
            patch("authglow.api.auth.get_settings", return_value=self.mock_settings),
            patch("authglow.api.auth.EmailVerificationService") as mock_ev_cls,
            patch("authglow.api.auth.get_email_service") as mock_email_factory,
        ):
            mock_ev = AsyncMock()
            mock_ev.create_verification_token.return_value = MagicMock(
                verification_code="WXYZ-QRST-2345"
            )
            mock_ev_cls.return_value = mock_ev
            mock_email_svc = AsyncMock()
            mock_email_factory.return_value = mock_email_svc

            await register_user(
                request=request,
                user_data=user_data,
                storage=self.mock_storage,
                password_validator=self.mock_validator,
                audit_service=self.mock_audit,
            )

            self.mock_audit.log_event.assert_awaited_once()
            call_kwargs = self.mock_audit.log_event.call_args[1]
            assert call_kwargs["event_type"] == "user_registered"
            assert call_kwargs["email"] == "audit@example.com"
