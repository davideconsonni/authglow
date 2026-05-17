import pytest
from datetime import datetime, timedelta


class TestRefreshTokenLifecycle:
    def test_create_refresh_token(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-1",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        assert rt is not None
        assert rt.user_id == "user-rt-1"
        assert rt.client_id == "test-client"
        assert not rt.used
        assert not rt.revoked

    def test_get_refresh_token(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-2", client_id="test-client", scopes=["read"]
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched is not None
        assert fetched.token_id == rt.token_id

    def test_validate_and_rotate(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-3", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="test-client"
            )
        )
        assert new_rt is not None
        assert error is None
        assert new_rt.parent_token_id == rt.token_id

    def test_validate_and_rotate_wrong_client(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-4", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="wrong-client"
            )
        )
        assert new_rt is None
        assert "Client mismatch" in error

    def test_validate_and_rotate_revoked_token(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-5", client_id="test-client", scopes=["read"]
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token)
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="test-client"
            )
        )
        assert new_rt is None
        assert "revoked" in error.lower()

    def test_reuse_detection_revokes_family(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-6", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, _ = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="test-client"
            )
        )
        assert new_rt is not None
        reuse_result, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="test-client"
            )
        )
        assert reuse_result is None
        assert "reuse" in error.lower() or "revoked" in error.lower()

    def test_revoke_token(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-7", client_id="test-client", scopes=["read"]
            )
        )
        result = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="Manual revoke")
        )
        assert result is True

    def test_revoke_user_tokens(self, refresh_token_service):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-8", client_id="test-client", scopes=["read"]
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-8", client_id="test-client", scopes=["write"]
            )
        )
        count = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_user_tokens("user-rt-8")
        )
        assert count >= 2
