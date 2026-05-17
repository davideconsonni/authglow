import pytest
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken


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


class TestCreateResetToken:
    def test_create_reset_token(self, password_reset_service):
        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-1", email="user1@example.com"
            )
        )
        assert isinstance(token, PasswordResetToken)
        assert token.user_id == "user-1"
        assert token.email == "user1@example.com"
        assert token.token_hash.startswith("$2b$")
        assert token.is_used is False
        assert isinstance(plaintext, str)
        assert len(plaintext) > 20

    def test_token_hash_is_bcrypt(self, password_reset_service):
        import bcrypt

        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-1", email="user1@example.com"
            )
        )
        assert bcrypt.checkpw(plaintext.encode(), token.token_hash.encode())

    def test_token_plaintext_not_stored(self, password_reset_service):
        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-1", email="user1@example.com"
            )
        )
        assert plaintext not in token.model_dump_json()

    def test_create_with_ip_and_agent(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-2",
                email="user2@example.com",
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )
        )
        assert token.ip_address == "192.168.1.1"
        assert token.user_agent == "Mozilla/5.0"

    def test_custom_expiry(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-3",
                email="user3@example.com",
                expires_in_minutes=60,
            )
        )
        delta = token.expires_at - token.created_at
        assert delta >= timedelta(minutes=59)
        assert delta <= timedelta(minutes=61)


class TestVerifyToken:
    def test_verify_valid_token(self, password_reset_service):
        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-verify", email="verify@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is not None
        assert found.user_id == "user-verify"

    def test_verify_wrong_token(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-wrong", email="wrong@example.com"
            )
        )
        found = asyncio_run(password_reset_service.verify_token("wrong-token-value"))
        assert found is None

    def test_verify_used_token_returns_none(self, password_reset_service):
        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-used", email="used@example.com"
            )
        )
        asyncio_run(password_reset_service.mark_token_used(token.token_id))
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is None

    def test_verify_expired_token_returns_none(self, password_reset_service):
        token, plaintext = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-exp", email="exp@example.com"
            )
        )
        import json

        path = password_reset_service._get_token_path(token.token_id)
        data = token.model_dump(mode="json")
        data["expires_at"] = (utcnow() - timedelta(minutes=1)).isoformat()
        with password_reset_service.fs.open(path, "w") as f:
            json.dump(data, f)
        found = asyncio_run(password_reset_service.verify_token(plaintext))
        assert found is None


class TestMarkTokenUsed:
    def test_mark_token_used(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-m1", email="m1@example.com"
            )
        )
        result = asyncio_run(password_reset_service.mark_token_used(token.token_id))
        assert result is True

    def test_mark_token_used_twice_fails(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-m2", email="m2@example.com"
            )
        )
        result1 = asyncio_run(password_reset_service.mark_token_used(token.token_id))
        result2 = asyncio_run(password_reset_service.mark_token_used(token.token_id))
        assert result1 is True
        assert result2 is False

    def test_mark_nonexistent_token_fails(self, password_reset_service):
        result = asyncio_run(password_reset_service.mark_token_used("nonexistent"))
        assert result is False


class TestGetToken:
    def test_get_token_exists(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-get", email="get@example.com"
            )
        )
        found = asyncio_run(password_reset_service.get_token(token.token_id))
        assert found is not None
        assert found.user_id == "user-get"

    def test_get_token_not_found(self, password_reset_service):
        found = asyncio_run(password_reset_service.get_token("nonexistent-id"))
        assert found is None


class TestListTokens:
    def test_list_user_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-list", email="list1@example.com"
            )
        )
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-list", email="list1@example.com"
            )
        )
        tokens = asyncio_run(password_reset_service.list_user_tokens("user-list"))
        assert len(tokens) == 2

    def test_list_user_tokens_filters_other_users(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-a", email="a@example.com"
            )
        )
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-b", email="b@example.com"
            )
        )
        tokens = asyncio_run(password_reset_service.list_user_tokens("user-a"))
        assert all(t.user_id == "user-a" for t in tokens)

    def test_list_all_tokens_pagination(self, password_reset_service):
        for i in range(5):
            asyncio_run(
                password_reset_service.create_reset_token(
                    user_id=f"user-p{i}", email=f"p{i}@example.com"
                )
            )
        page1 = asyncio_run(password_reset_service.list_all_tokens(limit=2, offset=0))
        page2 = asyncio_run(password_reset_service.list_all_tokens(limit=2, offset=2))
        assert len(page1) <= 2
        assert len(page2) <= 2


class TestRevokeUserTokens:
    def test_revoke_user_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-revoke", email="revoke@example.com"
            )
        )
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-revoke", email="revoke@example.com"
            )
        )
        count = asyncio_run(password_reset_service.revoke_user_tokens("user-revoke"))
        assert count == 2


class TestCleanupExpiredTokens:
    def test_cleanup_expired_tokens(self, password_reset_service):
        token, _ = asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-cleanup", email="cleanup@example.com"
            )
        )
        asyncio_run(password_reset_service.mark_token_used(token.token_id))
        count = asyncio_run(password_reset_service.cleanup_expired_tokens())
        assert count >= 1


class TestGetStats:
    def test_get_stats_empty(self, password_reset_service):
        stats = asyncio_run(password_reset_service.get_stats())
        assert "total" in stats
        assert "active" in stats
        assert "expired" in stats
        assert "used" in stats

    def test_get_stats_with_tokens(self, password_reset_service):
        asyncio_run(
            password_reset_service.create_reset_token(
                user_id="user-stats", email="stats@example.com"
            )
        )
        stats = asyncio_run(password_reset_service.get_stats())
        assert stats["total"] >= 1
        assert stats["active"] >= 1
