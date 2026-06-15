"""Unit tests for the File-backed API-key repository.

Covers ``FileAPIKeyRepository``. The service-level behaviour
(brute-force lockout policy, ``named_lock``-guarded read-modify-
write critical sections, IP restrictions, bcrypt verify) is
exercised by ``tests/unit/test_api_key.py``.

The test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method, including
  the prefix-index helpers;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.api_key import APIKey
from authglow.repositories.file.api_key import FileAPIKeyRepository
from authglow.repositories.protocols import APIKeyRepository


def _make_api_key(
    key_id: str = "key-1",
    user_id: str = "user-1",
    prefix: str = "ak_test1234",
    is_active: bool = True,
    expires_at=None,
) -> APIKey:
    return APIKey(
        key_id=key_id,
        user_id=user_id,
        name="Test Key",
        key_prefix=prefix,
        key_hash="$2b$12$placeholder",
        scopes=["read"],
        is_active=is_active,
        expires_at=expires_at,
        created_by="admin-1",
    )


# ---------------------------------------------------------------------------
# FileAPIKeyRepository
# ---------------------------------------------------------------------------


class TestFileAPIKeyRepository:
    def _make_repo(self, test_settings) -> FileAPIKeyRepository:
        return FileAPIKeyRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "api_keys"
        assert Path(repo._storage_path).name == "api_keys"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, APIKeyRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in (
            "create",
            "get_by_id",
            "get_by_prefix",
            "update",
            "delete",
            "list_for_user",
            "list_all",
            "cleanup_expired",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    # ----- create / get_by_id -----

    async def test_create_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-rt", user_id="u-rt", prefix="ak_round1")
        await repo.create(key)
        loaded = await repo.get_by_id("k-rt")
        assert loaded is not None
        assert loaded.key_id == "k-rt"
        assert loaded.user_id == "u-rt"
        assert loaded.key_prefix == "ak_round1"

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nope") is None

    async def test_create_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-idem", prefix="ak_idem12")
        await repo.create(key)
        await repo.create(key)
        loaded = await repo.get_by_id("k-idem")
        assert loaded is not None
        assert loaded.key_id == "k-idem"

    async def test_corrupt_json_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        path = Path(repo._path_for("k-corrupt"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        assert await repo.get_by_id("k-corrupt") is None

    # ----- update -----

    async def test_update_persists_changes(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-upd", prefix="ak_upd1234")
        await repo.create(key)
        key.name = "Updated Name"
        key.scopes = ["read", "write"]
        await repo.update(key)
        loaded = await repo.get_by_id("k-upd")
        assert loaded is not None
        assert loaded.name == "Updated Name"
        assert loaded.scopes == ["read", "write"]

    # ----- delete -----

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_api_key(key_id="k-del", prefix="ak_del1234"))
        result = await repo.delete("k-del")
        assert result is True
        assert await repo.get_by_id("k-del") is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nope") is False

    # ----- prefix index helpers -----

    async def test_load_prefix_index_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.load_prefix_index("nope_prefix") == []

    async def test_add_to_prefix_index_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-idx", prefix="ak_idx1234")
        await repo.add_to_prefix_index(key)
        await repo.add_to_prefix_index(key)
        ids = await repo.load_prefix_index("ak_idx1234")
        assert ids == ["k-idx"]

    async def test_remove_from_prefix_index(self, test_settings):
        repo = self._make_repo(test_settings)
        key_a = _make_api_key(key_id="k-a", prefix="ak_pair123")
        key_b = _make_api_key(key_id="k-b", prefix="ak_pair123")
        await repo.add_to_prefix_index(key_a)
        await repo.add_to_prefix_index(key_b)
        await repo.remove_from_prefix_index("ak_pair123", "k-a")
        ids = await repo.load_prefix_index("ak_pair123")
        assert ids == ["k-b"]

    async def test_remove_from_prefix_index_deletes_when_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-only", prefix="ak_only12")
        await repo.add_to_prefix_index(key)
        index_path = Path(repo._index_path_for("ak_only12"))
        assert index_path.exists()
        await repo.remove_from_prefix_index("ak_only12", "k-only")
        assert not index_path.exists()
        assert await repo.load_prefix_index("ak_only12") == []

    async def test_remove_missing_key_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.remove_from_prefix_index("ak_nope12", "k-missing")

    # ----- get_by_prefix -----

    async def test_get_by_prefix_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_prefix("ak_nope12") == []

    async def test_get_by_prefix_returns_matching_candidates(self, test_settings):
        repo = self._make_repo(test_settings)
        key_a = _make_api_key(key_id="k-a", user_id="u-a", prefix="ak_share12")
        key_b = _make_api_key(key_id="k-b", user_id="u-b", prefix="ak_share12")
        key_c = _make_api_key(key_id="k-c", user_id="u-c", prefix="ak_other1")
        await repo.create(key_a)
        await repo.create(key_b)
        await repo.create(key_c)
        await repo.add_to_prefix_index(key_a)
        await repo.add_to_prefix_index(key_b)
        await repo.add_to_prefix_index(key_c)
        result = await repo.get_by_prefix("ak_share12")
        assert len(result) == 2
        assert {k.key_id for k in result} == {"k-a", "k-b"}

    async def test_get_by_prefix_skips_missing_documents(self, test_settings):
        repo = self._make_repo(test_settings)
        key = _make_api_key(key_id="k-orphan", prefix="ak_orphan1")
        await repo.add_to_prefix_index(key)  # index references missing doc
        result = await repo.get_by_prefix("ak_orphan1")
        assert result == []

    # ----- list_for_user / list_all -----

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_api_key(key_id="k-1", user_id="u-a", prefix="ak_a1234567"))
        await repo.create(_make_api_key(key_id="k-2", user_id="u-a", prefix="ak_a2345678"))
        await repo.create(_make_api_key(key_id="k-3", user_id="u-b", prefix="ak_b1234567"))
        result = await repo.list_for_user("u-a")
        assert len(result) == 2
        assert all(k.user_id == "u-a" for k in result)

    async def test_list_for_user_returns_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list_for_user("nobody") == []

    async def test_list_all_with_pagination(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(5):
            await repo.create(
                _make_api_key(
                    key_id=f"k-{i:02d}",
                    user_id=f"u-{i:02d}",
                    prefix=f"ak_p{i:08d}2",
                )
            )
        page1 = await repo.list_all(limit=2, offset=0)
        page2 = await repo.list_all(limit=2, offset=2)
        page3 = await repo.list_all(limit=2, offset=4)
        assert len(page1) == 2
        assert len(page2) == 2
        assert len(page3) == 1

    async def test_list_all_active_only_filter(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_api_key(key_id="k-active", prefix="ak_act12345", is_active=True))
        await repo.create(_make_api_key(key_id="k-revoked", prefix="ak_rev12345", is_active=False))
        result = await repo.list_all(active_only=True)
        assert len(result) == 1
        assert result[0].key_id == "k-active"

    # ----- cleanup_expired -----

    async def test_cleanup_expired_deletes_expired_and_inactive(self, test_settings):
        repo = self._make_repo(test_settings)
        key_ei = _make_api_key(
            key_id="k-ei",
            prefix="ak_ei123456",
            is_active=False,
            expires_at=utcnow() - timedelta(days=1),
        )
        key_ea = _make_api_key(
            key_id="k-ea",
            prefix="ak_ea123456",
            is_active=True,
            expires_at=utcnow() - timedelta(days=1),
        )
        key_ok = _make_api_key(key_id="k-ok", prefix="ak_ok123456", is_active=True)
        await repo.create(key_ei)
        await repo.create(key_ea)
        await repo.create(key_ok)
        await repo.add_to_prefix_index(key_ei)
        await repo.add_to_prefix_index(key_ea)
        await repo.add_to_prefix_index(key_ok)
        deleted = await repo.cleanup_expired()
        assert deleted == 1
        assert await repo.get_by_id("k-ei") is None
        assert await repo.get_by_id("k-ea") is not None  # active + expired is kept
        assert await repo.get_by_id("k-ok") is not None
        # prefix index entry for the deleted key is gone
        assert await repo.load_prefix_index("ak_ei123456") == []


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileAPIKeyRepositoryWithPatchedSettings:
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
            repo = FileAPIKeyRepository()
            assert Path(repo._storage_path).exists()
