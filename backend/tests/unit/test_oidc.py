import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from authglow.models.user import User
from authglow.services.password import hash_password


def asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_user(**kwargs):
    defaults = dict(
        id=kwargs.get("id", "test-oidc-user"),
        email=kwargs.get("email", "oidc@example.com"),
        hashed_password=hash_password("TestP@ss1!"),
        is_active=True,
        email_verified=True,
        scopes=kwargs.get("scopes", ["read"]),
        first_name=kwargs.get("first_name", "Test"),
        last_name=kwargs.get("last_name", "User"),
    )
    defaults.update(kwargs)
    defaults.pop("id", None)
    defaults.pop("email", None)
    defaults.pop("scopes", None)
    defaults.pop("first_name", None)
    defaults.pop("last_name", None)
    return User(
        id=kwargs.get("id", "test-oidc-user"),
        email=kwargs.get("email", "oidc@example.com"),
        hashed_password=hash_password("TestP@ss1!"),
        is_active=True,
        email_verified=True,
        scopes=kwargs.get("scopes", ["read"]),
        first_name=kwargs.get("first_name", "Test"),
        last_name=kwargs.get("last_name", "User"),
    )


class TestGetUserInfo:
    def test_get_user_info_openid_scope(self, oidc_service):
        user = User(
            id="user-oidc-1",
            email="oidc1@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            first_name="John",
            last_name="Doe",
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(oidc_service.get_user_info("user-oidc-1", ["openid"]))
        assert result is not None
        assert result.sub == "user-oidc-1"
        assert result.email is None
        assert result.given_name is None

    def test_get_user_info_profile_scope(self, oidc_service):
        user = User(
            id="user-oidc-2",
            email="oidc2@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            first_name="Jane",
            last_name="Smith",
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(
            oidc_service.get_user_info("user-oidc-2", ["openid", "profile"])
        )
        assert result is not None
        assert result.sub == "user-oidc-2"
        assert result.given_name == "Jane"
        assert result.family_name == "Smith"
        assert result.name == "Jane Smith"

    def test_get_user_info_email_scope(self, oidc_service):
        user = User(
            id="user-oidc-3",
            email="oidc3@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(
            oidc_service.get_user_info("user-oidc-3", ["openid", "email"])
        )
        assert result is not None
        assert result.email == "oidc3@example.com"
        assert result.email_verified is True

    def test_get_user_info_permissions_scope(self, oidc_service):
        user = User(
            id="user-oidc-4",
            email="oidc4@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read", "write", "admin"],
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(
            oidc_service.get_user_info("user-oidc-4", ["openid", "permissions"])
        )
        assert result is not None
        assert result.sub == "user-oidc-4"

    def test_get_user_info_not_found(self, oidc_service):
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=None)

        result = asyncio_run(oidc_service.get_user_info("nonexistent", ["openid"]))
        assert result is None


class TestBuildUserClaims:
    def test_build_user_claims_profile(self, oidc_service):
        user = User(
            id="user-claims-1",
            email="claims1@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            first_name="Alice",
            last_name="Wonder",
        )
        claims = oidc_service.build_user_claims(user, ["openid", "profile"])
        assert "sub" not in claims
        assert claims.get("given_name") == "Alice"
        assert claims.get("family_name") == "Wonder"
        assert claims.get("name") == "Alice Wonder"

    def test_build_user_claims_email(self, oidc_service):
        user = User(
            id="user-claims-2",
            email="claims2@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        claims = oidc_service.build_user_claims(user, ["openid", "email"])
        assert claims.get("email") == "claims2@example.com"
        assert claims.get("email_verified") is True

    def test_build_user_claims_empty_scopes(self, oidc_service):
        user = User(
            id="user-claims-3",
            email="claims3@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        claims = oidc_service.build_user_claims(user, [])
        assert "email" not in claims
        assert "given_name" not in claims


class TestFilterClaimsByScopes:
    def test_filter_claims_openid(self, oidc_service):
        claims = {"sub": "user-1", "email": "test@example.com", "name": "Test User"}
        result = oidc_service.filter_claims_by_scopes(claims, ["openid"])
        assert "sub" in result

    def test_filter_claims_email(self, oidc_service):
        claims = {
            "sub": "user-1",
            "email": "test@example.com",
            "email_verified": True,
            "name": "Test User",
        }
        result = oidc_service.filter_claims_by_scopes(claims, ["openid", "email"])
        assert "sub" in result
        assert "email" in result
        assert "email_verified" in result
        assert "name" not in result

    def test_filter_claims_profile(self, oidc_service):
        claims = {
            "sub": "user-1",
            "name": "Test User",
            "given_name": "Test",
            "family_name": "User",
            "email": "test@example.com",
        }
        result = oidc_service.filter_claims_by_scopes(claims, ["openid", "profile"])
        assert "name" in result
        assert "given_name" in result
        assert "email" not in result

    def test_filter_claims_unknown_scope(self, oidc_service):
        claims = {"sub": "user-1", "custom": "value"}
        result = oidc_service.filter_claims_by_scopes(claims, ["unknown_scope"])
        assert "sub" not in result
        assert "custom" not in result

    def test_filter_claims_multiple_scopes(self, oidc_service):
        claims = {
            "sub": "user-1",
            "name": "Test",
            "email": "test@example.com",
            "email_verified": True,
            "phone_number": "+1234567890",
        }
        result = oidc_service.filter_claims_by_scopes(
            claims, ["openid", "email", "phone"]
        )
        assert "sub" in result
        assert "email" in result
        assert "email_verified" in result
        assert "phone_number" in result
        assert "name" not in result
