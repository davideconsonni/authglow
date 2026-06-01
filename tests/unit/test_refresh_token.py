import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock


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


class TestRefreshTokenPrefixIndex:
    """Tests for prefix-indexed refresh token lookup (P1 performance fix)."""

    def test_prefix_index_file_created_on_create(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-1",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        from authglow.services.refresh_token import PREFIX_LENGTH

        prefix = rt.token[:PREFIX_LENGTH]
        index_file = f"{refresh_token_service.index_path}/{prefix}.json"

        import os

        assert os.path.exists(index_file)
        import json

        with open(index_file, "r") as f:
            idx = json.load(f)
        assert rt.token_id in idx["token_ids"]

    def test_get_refresh_token_no_glob(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-2",
                client_id="test-client",
                scopes=["read"],
            )
        )
        original_glob = refresh_token_service._afs.glob

        def _glob_should_not_be_called(*args, **kwargs):
            raise AssertionError("glob() was called — prefix index NOT used!")

        refresh_token_service._afs.glob = _glob_should_not_be_called
        try:
            fetched = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.get_refresh_token(rt.token)
            )
            assert fetched is not None
            assert fetched.token_id == rt.token_id
        finally:
            refresh_token_service._afs.glob = original_glob

    def test_unknown_prefix_returns_none(self, refresh_token_service):
        import asyncio
        import secrets

        fake_token = secrets.token_urlsafe(32)
        result = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(fake_token)
        )
        assert result is None

    def test_revoke_preserves_index_entry(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-3",
                client_id="test-client",
                scopes=["read"],
            )
        )
        from authglow.services.refresh_token import PREFIX_LENGTH

        prefix = rt.token[:PREFIX_LENGTH]

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="test revoke")
        )
        candidate_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_prefix_index(prefix)
        )
        assert rt.token_id in candidate_ids

    def test_cleanup_removes_from_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-4",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=-1,
            )
        )
        from authglow.services.refresh_token import PREFIX_LENGTH

        prefix = rt.token[:PREFIX_LENGTH]

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.cleanup_expired_tokens()
        )
        candidate_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_prefix_index(prefix)
        )
        assert rt.token_id not in candidate_ids

    def test_prefix_index_isolates_lookups(self, refresh_token_service):
        import asyncio

        target_rt = None
        for i in range(10):
            rt = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.create_refresh_token(
                    user_id=f"user-pi-5-{i}",
                    client_id="test-client",
                    scopes=["read"],
                )
            )
            if i == 5:
                target_rt = rt

        from authglow.services.refresh_token import PREFIX_LENGTH

        prefix = target_rt.token[:PREFIX_LENGTH]
        candidate_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_prefix_index(prefix)
        )
        assert len(candidate_ids) <= 2

        original_glob = refresh_token_service._afs.glob

        def _glob_must_not_called(*args, **kwargs):
            raise AssertionError("glob() was called — prefix index NOT used!")

        refresh_token_service._afs.glob = _glob_must_not_called
        try:
            fetched = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.get_refresh_token(target_rt.token)
            )
            assert fetched is not None
            assert fetched.token_id == target_rt.token_id
        finally:
            refresh_token_service._afs.glob = original_glob

    def test_prefix_collision_both_resolved(self, refresh_token_service):
        import asyncio

        rt_a = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-a",
                client_id="test-client",
                scopes=["read"],
            )
        )
        rt_b = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-b",
                client_id="test-client",
                scopes=["write"],
            )
        )
        from authglow.services.refresh_token import PREFIX_LENGTH

        prefix_a = rt_a.token[:PREFIX_LENGTH]
        prefix_b = rt_b.token[:PREFIX_LENGTH]

        if prefix_a == prefix_b:
            pytest.skip("Prefixes happen to collide naturally — test already covered")

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service._save_prefix_index(prefix_a, rt_b.token_id)
        )

        candidate_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_prefix_index(prefix_a)
        )
        assert rt_a.token_id in candidate_ids
        assert rt_b.token_id in candidate_ids

        fetched_a = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt_a.token)
        )
        assert fetched_a is not None
        assert fetched_a.token_id == rt_a.token_id

        fetched_b = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt_b.token)
        )
        assert fetched_b is not None
        assert fetched_b.token_id == rt_b.token_id

    def test_revoked_token_still_found_via_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-pi-6",
                client_id="test-client",
                scopes=["read"],
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="test")
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched is not None
        assert fetched.revoked is True


class TestRefreshTokenCache:
    """Tests for in-memory TTL cache on get_refresh_token (P6 performance)."""

    def test_cache_hit_skips_prefix_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-cache-1",
                client_id="test-client",
                scopes=["read"],
            )
        )
        fetched_1 = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched_1 is not None

        original_load = refresh_token_service._load_prefix_index

        def _load_must_not_be_called(*args, **kwargs):
            raise AssertionError("_load_prefix_index() called — cache was NOT hit!")

        refresh_token_service._load_prefix_index = _load_must_not_be_called
        try:
            fetched_2 = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.get_refresh_token(rt.token)
            )
            assert fetched_2 is not None
            assert fetched_2.token_id == rt.token_id
        finally:
            refresh_token_service._load_prefix_index = original_load

    def test_cache_stale_entry_evicted_on_file_missing(self, refresh_token_service):
        import asyncio
        import os

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-cache-1b",
                client_id="test-client",
                scopes=["read"],
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched is not None

        token_path = refresh_token_service._get_token_path(rt.token_id)
        os.remove(token_path)

        fetched_2 = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched_2 is None

    def test_cache_invalidation_on_revoke(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-cache-2",
                client_id="test-client",
                scopes=["read"],
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched is not None
        assert fetched.revoked is False

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="test")
        )
        fetched_after = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched_after is not None
        assert fetched_after.revoked is True

    def test_cache_invalidation_on_cleanup(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-cache-3",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=-1,
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched is not None

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.cleanup_expired_tokens()
        )
        fetched_after = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)
        )
        assert fetched_after is None


class TestRefreshTokenActiveIndex:
    """Tests for active token index (P4 performance fix)."""

    def test_active_index_created_on_create(self, refresh_token_service):
        import asyncio
        import os, json

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-1",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        assert os.path.exists(refresh_token_service._active_index_path)
        with open(refresh_token_service._active_index_path, "r") as f:
            idx = json.load(f)
        assert rt.token_id in idx["token_ids"]

    def test_revoked_token_removed_from_active_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-2",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="test revoke")
        )

        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_active_index()
        )
        assert rt.token_id not in active_ids

    def test_rotation_updates_active_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-3",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token, client_id="test-client"
            )
        )
        assert new_rt is not None
        assert error is None

        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_active_index()
        )
        assert rt.token_id not in active_ids
        assert new_rt.token_id in active_ids

    def test_cleanup_removes_expired_from_active_index(self, refresh_token_service):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-4",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=-1,
            )
        )

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.cleanup_expired_tokens()
        )

        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._load_active_index()
        )
        assert rt.token_id not in active_ids

    def test_list_all_tokens_active_only_uses_index_not_glob(
        self, refresh_token_service
    ):
        import asyncio

        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-5",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        original_glob = refresh_token_service._afs.glob

        def _glob_must_not_be_called(*args, **kwargs):
            raise AssertionError("glob() was called — active index NOT used!")

        refresh_token_service._afs.glob = _glob_must_not_be_called
        try:
            tokens, total = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.list_all_tokens(active_only=True)
            )
            assert total == 1
            assert tokens[0].token_id == rt.token_id
        finally:
            refresh_token_service._afs.glob = original_glob

    def test_list_all_tokens_active_only_excludes_revoked(self, refresh_token_service):
        import asyncio

        rt_active = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-6a",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        rt_revoked = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-6b",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt_revoked.token, reason="test")
        )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True)
        )
        assert total == 1
        assert tokens[0].token_id == rt_active.token_id

    def test_list_all_tokens_active_only_filters_by_user_id(
        self, refresh_token_service
    ):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-7a",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-7b",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(
                active_only=True, user_id="user-ai-7a"
            )
        )
        assert total == 1
        assert tokens[0].user_id == "user-ai-7a"

    def test_list_all_tokens_active_only_pagination(self, refresh_token_service):
        import asyncio

        for i in range(5):
            asyncio.get_event_loop().run_until_complete(
                refresh_token_service.create_refresh_token(
                    user_id=f"user-ai-8-{i}",
                    client_id="test-client",
                    scopes=["read"],
                    expires_in_days=30,
                )
            )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True, limit=2, offset=0)
        )
        assert total == 5
        assert len(tokens) == 2

        tokens2, total2 = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True, limit=2, offset=2)
        )
        assert total2 == 5
        assert len(tokens2) == 2
        page1_ids = {t.token_id for t in tokens}
        page2_ids = {t.token_id for t in tokens2}
        assert page1_ids.isdisjoint(page2_ids)

    def test_empty_active_index_returns_empty_list(self, refresh_token_service):
        import asyncio

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True)
        )
        assert tokens == []
        assert total == 0

    def test_user_id_no_match_returns_empty(self, refresh_token_service):
        import asyncio

        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-10",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )

        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(
                active_only=True, user_id="non-existent-user"
            )
        )
        assert tokens == []
        assert total == 0
