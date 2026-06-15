import asyncio
import json
import os
import secrets

import pytest
from datetime import timedelta
from unittest.mock import patch, MagicMock

from authglow.core.datetime import utcnow


class TestRefreshTokenLifecycle:
    def test_create_refresh_token(self, refresh_token_service):
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
        assert rt.token is not None
        assert len(rt.token) > 30

    def test_get_refresh_token(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-2", client_id="test-client", scopes=["read"]
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(rt.token)  # type: ignore[arg-type]
        )
        assert fetched is not None
        assert fetched.token_id == rt.token_id
        assert fetched.token == rt.token  # plaintext restored in memory

    def test_validate_and_rotate(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-3", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token,
                client_id="test-client",  # type: ignore[arg-type]
            )
        )
        assert new_rt is not None
        assert error is None
        assert new_rt.parent_token_id == rt.token_id

    def test_validate_and_rotate_wrong_client(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-4", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token,
                client_id="wrong-client",  # type: ignore[arg-type]
            )
        )
        assert new_rt is None
        assert "Client mismatch" in error

    def test_validate_and_rotate_revoked_token(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-5", client_id="test-client", scopes=["read"]
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token)  # type: ignore[arg-type]
        )
        new_rt, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token,
                client_id="test-client",  # type: ignore[arg-type]
            )
        )
        assert new_rt is None
        assert "revoked" in error.lower()

    def test_reuse_detection_revokes_family(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-6", client_id="test-client", scopes=["read"]
            )
        )
        new_rt, _ = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token,
                client_id="test-client",  # type: ignore[arg-type]
            )
        )
        assert new_rt is not None
        reuse_result, error = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.validate_and_rotate(
                token=rt.token,
                client_id="test-client",  # type: ignore[arg-type]
            )
        )
        assert reuse_result is None
        assert "reuse" in error.lower() or "revoked" in error.lower()

    def test_revoke_token(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-rt-7", client_id="test-client", scopes=["read"]
            )
        )
        result = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="Manual revoke")  # type: ignore[arg-type]
        )
        assert result is True

    def test_revoke_user_tokens(self, refresh_token_service):
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


class TestRefreshTokenHashedStorage:
    """VAPT-002: Tokens must NOT be stored in plaintext on disk."""

    def test_plaintext_not_on_disk(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-1",
                client_id="test-client",
                scopes=["read"],
            )
        )
        path = refresh_token_service._repo._path_for_lookup(rt.token_lookup)
        raw = open(path, "r").read()

        assert rt.token not in raw
        assert rt.token_hash in raw
        assert rt.token_lookup in raw

    def test_token_lookup_is_hmac(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-2",
                client_id="test-client",
                scopes=["read"],
            )
        )
        assert len(rt.token_lookup) == 64
        assert all(c in "0123456789abcdef" for c in rt.token_lookup)

    def test_token_hash_is_bcrypt(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-3",
                client_id="test-client",
                scopes=["read"],
            )
        )
        assert rt.token_hash.startswith("$2b$") or rt.token_hash.startswith("$2a$")

    def test_direct_hmac_lookup_o1(self, refresh_token_service):
        """O(1) lookup via HMAC — no directory scanning."""
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-4",
                client_id="test-client",
                scopes=["read"],
            )
        )
        original_glob = refresh_token_service._repo._glob

        def _glob_must_not_be_called(*args, **kwargs):
            raise AssertionError("glob() was called — should use O(1) HMAC lookup!")

        refresh_token_service._repo._glob = _glob_must_not_be_called
        try:
            fetched = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.get_refresh_token(rt.token)  # type: ignore[arg-type]
            )
            assert fetched is not None
            assert fetched.token_id == rt.token_id
        finally:
            refresh_token_service._repo._glob = original_glob

    def test_unknown_token_returns_none(self, refresh_token_service):
        fake_token = secrets.token_urlsafe(32)
        result = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token(fake_token)
        )
        assert result is None

    def test_wrong_secret_does_not_match(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-5",
                client_id="test-client",
                scopes=["read"],
            )
        )
        import hmac, hashlib

        wrong_lookup = hmac.new(b"wrong-secret", rt.token.encode(), hashlib.sha256).hexdigest()  # type: ignore[union-attr]
        assert wrong_lookup != rt.token_lookup

    def test_get_by_token_id_uses_id_index(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-6",
                client_id="test-client",
                scopes=["read"],
            )
        )
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token_by_id(rt.token_id)
        )
        assert fetched is not None
        assert fetched.token_id == rt.token_id

    def test_id_index_cleaned_up(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-h-7",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=-1,
            )
        )
        asyncio.get_event_loop().run_until_complete(refresh_token_service.cleanup_expired_tokens())
        fetched = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.get_refresh_token_by_id(rt.token_id)
        )
        assert fetched is None


class TestRefreshTokenActiveIndex:
    """Tests for active token index (P4 performance fix)."""

    def test_active_index_created_on_create(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-1",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        assert os.path.exists(refresh_token_service._repo._active_index_path)
        with open(refresh_token_service._repo._active_index_path, "r") as f:
            idx = json.load(f)
        assert rt.token_id in idx["token_ids"]

    def test_revoked_token_removed_from_active_index(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-2",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.revoke_token(rt.token, reason="test revoke")  # type: ignore[arg-type]
        )
        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._repo.load_active_index()
        )
        assert rt.token_id not in active_ids

    def test_rotation_updates_active_index(self, refresh_token_service):
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
                token=rt.token,
                client_id="test-client",  # type: ignore[arg-type]
            )
        )
        assert new_rt is not None
        assert error is None

        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._repo.load_active_index()
        )
        assert rt.token_id not in active_ids
        assert new_rt.token_id in active_ids

    def test_cleanup_removes_expired_from_active_index(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-4",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=-1,
            )
        )
        asyncio.get_event_loop().run_until_complete(refresh_token_service.cleanup_expired_tokens())
        active_ids = asyncio.get_event_loop().run_until_complete(
            refresh_token_service._repo.load_active_index()
        )
        assert rt.token_id not in active_ids

    def test_list_all_tokens_active_only_uses_index_not_glob(self, refresh_token_service):
        rt = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-5",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        original_glob = refresh_token_service._repo._glob

        def _glob_must_not_be_called(*args, **kwargs):
            raise AssertionError("glob() was called — active index NOT used!")

        refresh_token_service._repo._glob = _glob_must_not_be_called
        try:
            tokens, total = asyncio.get_event_loop().run_until_complete(
                refresh_token_service.list_all_tokens(active_only=True)
            )
            assert total == 1
            assert tokens[0].token_id == rt.token_id
        finally:
            refresh_token_service._repo._glob = original_glob

    def test_list_all_tokens_active_only_excludes_revoked(self, refresh_token_service):
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
            refresh_token_service.revoke_token(rt_revoked.token, reason="test")  # type: ignore[arg-type]
        )
        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True)
        )
        assert total == 1
        assert tokens[0].token_id == rt_active.token_id

    def test_list_all_tokens_active_only_filters_by_user_id(self, refresh_token_service):
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
            refresh_token_service.list_all_tokens(active_only=True, user_id="user-ai-7a")
        )
        assert total == 1
        assert tokens[0].user_id == "user-ai-7a"

    def test_list_all_tokens_active_only_pagination(self, refresh_token_service):
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
        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True)
        )
        assert tokens == []
        assert total == 0

    def test_user_id_no_match_returns_empty(self, refresh_token_service):
        asyncio.get_event_loop().run_until_complete(
            refresh_token_service.create_refresh_token(
                user_id="user-ai-10",
                client_id="test-client",
                scopes=["read"],
                expires_in_days=30,
            )
        )
        tokens, total = asyncio.get_event_loop().run_until_complete(
            refresh_token_service.list_all_tokens(active_only=True, user_id="non-existent-user")
        )
        assert tokens == []
        assert total == 0
