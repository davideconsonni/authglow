"""Unit tests for the File-backed refresh-token repository.

Covers ``FileRefreshTokenRepository``. The service-level behaviour
(``named_lock``, ``MAX_CAS_RETRIES`` retry loop, bcrypt verify,
token reuse detection, family revocation) is exercised by
``tests/unit/test_refresh_token.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method, including
  the two secondary indexes (``id_index`` and ``active_index``);
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

from authglow.core.datetime import utcnow
from authglow.models.refresh_token import RefreshToken
from authglow.repositories.file.refresh_token import (
    FileRefreshTokenRepository,
)
from authglow.repositories.protocols import RefreshTokenRepository


def _make_token(
    token_id: str = "tok-1",
    token_lookup: str = "lookup-1",
    user_id: str = "user-1",
    *,
    expires_in_days: int = 30,
    used: bool = False,
    revoked: bool = False,
) -> RefreshToken:
    return RefreshToken(
        token_id=token_id,
        token_hash="$2b$12$placeholder",
        token_lookup=token_lookup,
        user_id=user_id,
        client_id="test-client",
        scopes=["read"],
        expires_at=utcnow() + timedelta(days=expires_in_days),
        used=used,
        revoked=revoked,
    )


# ---------------------------------------------------------------------------
# FileRefreshTokenRepository
# ---------------------------------------------------------------------------


class TestFileRefreshTokenRepository:
    def _make_repo(self, test_settings) -> FileRefreshTokenRepository:
        return FileRefreshTokenRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "refresh_tokens"
        assert Path(repo._storage_path).name == "refresh_tokens"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, RefreshTokenRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in (
            "create",
            "get_by_id",
            "get_by_lookup",
            "update",
            "delete",
            "list_active",
            "list_all",
            "cleanup_expired",
            "revoke_user_tokens",
            "load_id_index",
            "add_to_id_index",
            "remove_from_id_index",
            "load_active_index",
            "add_to_active_index",
            "remove_from_active_index",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    # ----- create / get_by_lookup -----

    async def test_create_and_get_by_lookup_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-rt", token_lookup="lookup-rt")
        await repo.create(token)
        loaded = await repo.get_by_lookup("lookup-rt")
        assert loaded is not None
        assert loaded.token_id == "k-rt"
        assert loaded.token_lookup == "lookup-rt"

    async def test_get_by_lookup_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_lookup("nope") is None

    async def test_create_does_not_persist_plaintext_token(self, test_settings):
        """VAPT-002: the plaintext token is never written to disk."""
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-vapt", token_lookup="lookup-vapt")
        # Manually set the plaintext attribute to verify it is not persisted
        token.token = "PLAINTEXT-SECRET"
        await repo.create(token)
        path = Path(repo._path_for_lookup("lookup-vapt"))
        raw = path.read_text()
        assert "PLAINTEXT-SECRET" not in raw

    # ----- get_by_id + id_index -----

    async def test_get_by_id_via_id_index(self, test_settings):
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-byid", token_lookup="lookup-byid")
        await repo.create(token)
        await repo.add_to_id_index("k-byid", "lookup-byid")
        loaded = await repo.get_by_id("k-byid")
        assert loaded is not None
        assert loaded.token_id == "k-byid"

    async def test_get_by_id_returns_none_for_missing_id(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nobody") is None

    async def test_id_index_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_id_index("k-1", "lookup-1")
        await repo.add_to_id_index("k-2", "lookup-2")
        idx = await repo.load_id_index()
        assert idx == {"k-1": "lookup-1", "k-2": "lookup-2"}

    async def test_add_to_id_index_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_id_index("k-1", "lookup-1")
        await repo.add_to_id_index("k-1", "lookup-1")
        idx = await repo.load_id_index()
        assert idx == {"k-1": "lookup-1"}

    async def test_remove_from_id_index(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_id_index("k-1", "lookup-1")
        await repo.add_to_id_index("k-2", "lookup-2")
        await repo.remove_from_id_index("k-1")
        idx = await repo.load_id_index()
        assert idx == {"k-2": "lookup-2"}

    async def test_remove_from_id_index_when_empty_deletes_file(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_id_index("k-only", "lookup-only")
        path = Path(repo._id_index_path)
        assert path.exists()
        await repo.remove_from_id_index("k-only")
        assert not path.exists()
        assert await repo.load_id_index() == {}

    async def test_remove_from_id_index_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.remove_from_id_index("nope")

    # ----- update with CAS -----

    async def test_update_persists_changes(self, test_settings):
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-upd", token_lookup="lookup-upd")
        await repo.create(token)
        token.used = True
        await repo.update(token)
        loaded = await repo.get_by_lookup("lookup-upd")
        assert loaded is not None
        assert loaded.used is True

    async def test_update_missing_raises(self, test_settings):
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-miss", token_lookup="lookup-miss")
        with pytest.raises(FileNotFoundError):
            await repo.update(token)

    # ----- delete -----

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        token = _make_token(token_id="k-del", token_lookup="lookup-del")
        await repo.create(token)
        await repo.add_to_id_index("k-del", "lookup-del")
        result = await repo.delete("k-del")
        assert result is True
        assert await repo.get_by_id("k-del") is None
        assert await repo.get_by_lookup("lookup-del") is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nobody") is False

    # ----- active_index -----

    async def test_active_index_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_active_index("k-1")
        await repo.add_to_active_index("k-2")
        ids = await repo.load_active_index()
        assert ids == ["k-1", "k-2"]

    async def test_add_to_active_index_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_active_index("k-1")
        await repo.add_to_active_index("k-1")
        ids = await repo.load_active_index()
        assert ids == ["k-1"]

    async def test_remove_from_active_index(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_active_index("k-1")
        await repo.add_to_active_index("k-2")
        await repo.remove_from_active_index("k-1")
        ids = await repo.load_active_index()
        assert ids == ["k-2"]

    async def test_remove_from_active_index_when_empty_deletes_file(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add_to_active_index("k-only")
        path = Path(repo._active_index_path)
        assert path.exists()
        await repo.remove_from_active_index("k-only")
        assert not path.exists()
        assert await repo.load_active_index() == []

    async def test_remove_from_active_index_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.remove_from_active_index("nope")

    # ----- list_active (via active_index) -----

    async def test_list_active_returns_only_active(self, test_settings):
        repo = self._make_repo(test_settings)
        t_active = _make_token(token_id="k-a", token_lookup="lookup-a")
        t_revoked = _make_token(token_id="k-r", token_lookup="lookup-r", revoked=True)
        t_expired = _make_token(token_id="k-e", token_lookup="lookup-e", expires_in_days=-1)
        for t in (t_active, t_revoked, t_expired):
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
        await repo.add_to_active_index("k-a")
        # intentionally NOT adding k-r or k-e to active index — they should
        # never appear in list_active
        result = await repo.list_active()
        assert len(result) == 1
        assert result[0].token_id == "k-a"

    async def test_list_active_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        t_a = _make_token(token_id="k-a", token_lookup="lookup-a", user_id="u-a")
        t_b = _make_token(token_id="k-b", token_lookup="lookup-b", user_id="u-b")
        for t in (t_a, t_b):
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
            await repo.add_to_active_index(t.token_id)
        result = await repo.list_active(user_id="u-a")
        assert len(result) == 1
        assert result[0].user_id == "u-a"

    async def test_list_active_returns_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list_active() == []

    # ----- list_all -----

    async def test_list_all_pagination(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(5):
            t = _make_token(
                token_id=f"k-{i:02d}",
                token_lookup=f"lookup-{i:02d}",
                user_id=f"u-{i:02d}",
            )
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
        page1, total1 = await repo.list_all(limit=2, offset=0)
        page2, total2 = await repo.list_all(limit=2, offset=2)
        assert total1 == 5
        assert total2 == 5
        assert len(page1) == 2
        assert len(page2) == 2

    async def test_list_all_active_only_uses_index(self, test_settings):
        repo = self._make_repo(test_settings)
        t = _make_token(token_id="k-active", token_lookup="lookup-active")
        await repo.create(t)
        await repo.add_to_id_index(t.token_id, t.token_lookup)
        await repo.add_to_active_index(t.token_id)
        page, total = await repo.list_all(active_only=True, limit=10, offset=0)
        assert total == 1
        assert page[0].token_id == "k-active"

    async def test_list_all_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        for uid in ("u-a", "u-b"):
            t = _make_token(
                token_id=f"k-{uid}",
                token_lookup=f"lookup-{uid}",
                user_id=uid,
            )
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
        page, total = await repo.list_all(user_id="u-a")
        assert total == 1
        assert page[0].user_id == "u-a"

    # ----- revoke_user_tokens -----

    async def test_revoke_user_tokens(self, test_settings):
        repo = self._make_repo(test_settings)
        t_a = _make_token(token_id="k-a", token_lookup="lookup-a", user_id="u-1")
        t_b = _make_token(token_id="k-b", token_lookup="lookup-b", user_id="u-1")
        t_other = _make_token(token_id="k-c", token_lookup="lookup-c", user_id="u-2")
        for t in (t_a, t_b, t_other):
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
            await repo.add_to_active_index(t.token_id)
        count = await repo.revoke_user_tokens(user_id="u-1")
        assert count == 2
        # Active index for u-1's tokens is empty
        ids = await repo.load_active_index()
        assert "k-a" not in ids
        assert "k-b" not in ids
        assert "k-c" in ids  # u-2's token is untouched

    async def test_revoke_user_tokens_with_client_filter(self, test_settings):
        repo = self._make_repo(test_settings)
        t_a = _make_token(
            token_id="k-a",
            token_lookup="lookup-a",
            user_id="u-1",
        )
        t_a.client_id = "client-1"
        t_b = _make_token(
            token_id="k-b",
            token_lookup="lookup-b",
            user_id="u-1",
        )
        t_b.client_id = "client-2"
        for t in (t_a, t_b):
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
            await repo.add_to_active_index(t.token_id)
        count = await repo.revoke_user_tokens(user_id="u-1", client_id="client-1")
        assert count == 1

    async def test_revoke_user_tokens_skips_already_revoked(self, test_settings):
        repo = self._make_repo(test_settings)
        t = _make_token(token_id="k-r", token_lookup="lookup-r", revoked=True)
        await repo.create(t)
        await repo.add_to_id_index(t.token_id, t.token_lookup)
        count = await repo.revoke_user_tokens(user_id="user-1")
        assert count == 0

    # ----- cleanup_expired -----

    async def test_cleanup_expired_deletes_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        t_exp = _make_token(
            token_id="k-exp",
            token_lookup="lookup-exp",
            expires_in_days=-1,
        )
        t_ok = _make_token(token_id="k-ok", token_lookup="lookup-ok", expires_in_days=30)
        for t in (t_exp, t_ok):
            await repo.create(t)
            await repo.add_to_id_index(t.token_id, t.token_lookup)
            await repo.add_to_active_index(t.token_id)
        deleted = await repo.cleanup_expired()
        assert deleted == 1
        assert await repo.get_by_id("k-exp") is None
        assert await repo.get_by_id("k-ok") is not None
        # id_index + active_index for the expired token are gone
        assert "k-exp" not in await repo.load_id_index()
        assert "k-exp" not in await repo.load_active_index()

    # ----- _collect skips index files -----

    async def test_collect_skips_index_files(self, test_settings):
        repo = self._make_repo(test_settings)
        # Manually write a "noise" file with a non-token content to verify
        # _collect ignores it (no schema validation needed, just naming)
        noise_path = Path(repo._storage_path) / "garbage.json"
        noise_path.write_text('{"not": "a token"}')
        tokens = await repo._collect()
        # garbage.json is not a valid RefreshToken but doesn't break the scan
        assert all(t.token_id != "garbage" for t in tokens)


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileRefreshTokenRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            repo = FileRefreshTokenRepository()
            assert Path(repo._storage_path).exists()
