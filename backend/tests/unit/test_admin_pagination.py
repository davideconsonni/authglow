import asyncio

import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta, timezone

asyncio.set_event_loop(asyncio.new_event_loop())


class TestUserStoragePagination:
    def test_count_users_empty(self, storage):
        import asyncio

        count = asyncio.get_event_loop().run_until_complete(storage.count_users())
        assert count == 0

    def test_count_users_with_data(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        for i in range(3):
            user = User(
                email=f"count{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

        count = asyncio.get_event_loop().run_until_complete(storage.count_users())
        assert count == 3

    def test_get_user_stats(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        user_active = User(
            email="stat_active@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            mfa_enabled=True,
            mfa_verified=True,
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user_active))

        user_inactive = User(
            email="stat_inactive@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=False,
            mfa_enabled=False,
            mfa_verified=False,
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user_inactive))

        stats = asyncio.get_event_loop().run_until_complete(storage.get_user_stats())
        assert stats["total"] == 2
        assert stats["active"] == 1
        assert stats["inactive"] == 1
        assert stats["mfa"] == 1

    def test_list_users_with_search_filter(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        for i in range(5):
            user = User(
                email=f"search{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=(i % 2 == 0),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

        page, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(search="search2")
        )
        assert total == 1
        assert page[0].email == "search2@example.com"

    def test_list_users_with_active_filter(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        for i in range(4):
            user = User(
                email=f"active_filter{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=(i < 2),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

        page, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=True)
        )
        assert total == 2
        for u in page:
            assert u.is_active is True

    def test_list_users_with_mfa_filter(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        user_mfa = User(
            email="mfa_yes@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            mfa_enabled=True,
            mfa_verified=True,
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user_mfa))

        user_no_mfa = User(
            email="mfa_no@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            mfa_enabled=False,
            mfa_verified=False,
            scopes=["read"],
        )
        asyncio.get_event_loop().run_until_complete(storage.create_user(user_no_mfa))

        page, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(mfa_enabled=True)
        )
        assert total == 1
        assert page[0].mfa_enabled is True

    def test_list_users_pagination_with_filters(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        for i in range(10):
            user = User(
                email=f"pagfilter{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=True,
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

        page, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(limit=3, offset=0, is_active=True)
        )
        assert len(page) == 3
        assert total == 10

        page2, total2 = asyncio.get_event_loop().run_until_complete(
            storage.list_users(limit=3, offset=3, is_active=True)
        )
        assert len(page2) == 3
        assert total2 == 10

    def test_list_users_returns_total_matching(self, storage):
        import asyncio
        from authglow.models.user import User
        from authglow.services.password import hash_password

        for i in range(5):
            user = User(
                email=f"totaltest{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=(i % 2 == 0),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

        page, total = asyncio.get_event_loop().run_until_complete(
            storage.list_users(is_active=True)
        )
        assert total == 3
        assert len(page) == 3


class TestRefreshTokenListAllTokens:
    def test_list_all_tokens_empty(self, refresh_token_service):
        import asyncio

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens()
        )
        assert tokens == []
        assert total == 0

    def test_list_all_tokens_with_data(self, refresh_token_service):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="rt-user-1",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="rt-user-2",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens()
        )
        assert total == 2
        assert len(tokens) == 2

    def test_list_all_tokens_pagination(self, refresh_token_service):
        import asyncio

        for i in range(5):
            asyncio.get_event_loop().run_until_complete(
                refresh_token_service.create_refresh_token(
                    user_id=f"rt-pag-user-{i}",
                    client_id="test-client",
                    scopes=["read"],
                    expires_in_days=30,
                )
            )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(limit=2, offset=0)
        )
        assert total == 5
        assert len(tokens) == 2

        tokens2, total2 = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(limit=2, offset=2)
        )
        assert total2 == 5
        assert len(tokens2) == 2

    def test_list_all_tokens_active_only(self, refresh_token_service):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="rt-active-user",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        token = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="rt-revoke-user",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        asyncio.get_event_loop().run_until_complete(refresh_token_service.revoke_token(token.token))

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True)
        )
        assert total == 1
        assert len(tokens) == 1


class TestPaginatedResponseModel:
    def test_paginated_response_creation(self):
        from authglow.models.admin import PaginatedResponse

        response = PaginatedResponse(
            items=[{"id": 1}, {"id": 2}],
            total=100,
            limit=50,
            offset=0,
        )
        assert len(response.items) == 2
        assert response.total == 100
        assert response.limit == 50
        assert response.offset == 0

    def test_paginated_response_empty(self):
        from authglow.models.admin import PaginatedResponse

        response = PaginatedResponse(items=[], total=0, limit=50, offset=0)
        assert response.items == []
        assert response.total == 0
