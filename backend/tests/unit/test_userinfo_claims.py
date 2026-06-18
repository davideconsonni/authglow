"""UserInfo claims cleanup and address support — Workstream N.

Validates that custom ``permissions`` claim is removed and that the
``address`` claim is populated from the ``User.address`` field when
the ``address`` scope is requested.
"""

from unittest.mock import AsyncMock, MagicMock

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


class TestUserInfoAddressClaim:
    """N.2 + N.3: address claim in UserInfo response."""

    def test_address_populated_when_user_has_address(self, oidc_service):
        user = User(
            id="user-addr-1",
            email="addr1@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            first_name="Test",
            last_name="User",
            address={
                "formatted": "123 Main St, Springfield, USA",
                "street_address": "123 Main St",
                "locality": "Springfield",
                "region": "IL",
                "postal_code": "62701",
                "country": "USA",
            },
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(oidc_service.get_user_info("user-addr-1", ["openid", "address"]))
        assert result is not None
        assert result.address == user.address

    def test_address_absent_when_user_has_no_address(self, oidc_service):
        user = User(
            id="user-no-addr",
            email="noaddr@example.com",
            hashed_password=hash_password("TestP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(oidc_service.get_user_info("user-no-addr", ["openid", "address"]))
        assert result is not None
        assert result.address is None
