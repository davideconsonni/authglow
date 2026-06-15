"""Unit tests for the File-backed login-history repository.

Covers ``FileLoginHistoryRepository``. The service-level behaviour
(``LoginHistoryEntry`` dataclass round-trip, ``RETENTION_DAYS``
sweep trigger on ``record_login``) is exercised by the integration
tests that hit ``api/admin.py`` with a mocked service — there is
no dedicated ``tests/unit/test_login_history.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.repositories.file.login_history import (
    FileLoginHistoryRepository,
)
from authglow.repositories.protocols import LoginHistoryRepository


def _make_entry(
    user_id: str = "user-1",
    email: str = "u@example.com",
    success: bool = True,
    *,
    ip: str | None = "10.0.0.1",
    ua: str | None = "TestUA/1.0",
    reason: str | None = None,
) -> dict:
    """Build a record dict (the post-refactor equivalent of
    ``LoginHistoryEntry.to_dict()``)."""
    return {
        "id": "fixed-id-for-test",
        "user_id": user_id,
        "email": email,
        "success": success,
        "ip_address": ip,
        "user_agent": ua,
        "failure_reason": reason,
        "timestamp": utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# FileLoginHistoryRepository
# ---------------------------------------------------------------------------


class TestFileLoginHistoryRepository:
    def _make_repo(self, test_settings) -> FileLoginHistoryRepository:
        return FileLoginHistoryRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "login_history"
        assert Path(repo._storage_path).name == "login_history"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, LoginHistoryRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("record", "list_for_user", "cleanup_old"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    # ----- record -----

    async def test_record_creates_user_subdir(self, test_settings):
        repo = self._make_repo(test_settings)
        record = _make_entry(user_id="u-rt")
        out = await repo.record(
            user_id=record["user_id"],
            email=record["email"],
            success=record["success"],
            ip_address=record["ip_address"],
            user_agent=record["user_agent"],
            failure_reason=record["failure_reason"],
            entry_id=record["id"],
            timestamp=record["timestamp"],
        )
        assert out["id"] == "fixed-id-for-test"
        assert out["user_id"] == "u-rt"
        user_dir = Path(repo._user_dir("u-rt"))
        assert user_dir.exists()
        assert user_dir.is_dir()

    async def test_record_writes_entry_file(self, test_settings):
        repo = self._make_repo(test_settings)
        record = _make_entry(user_id="u-w")
        await repo.record(
            user_id=record["user_id"],
            email=record["email"],
            success=record["success"],
            ip_address=record["ip_address"],
            user_agent=record["user_agent"],
            failure_reason=record["failure_reason"],
            entry_id=record["id"],
            timestamp=record["timestamp"],
        )
        path = Path(repo._entry_path("u-w", "fixed-id-for-test"))
        assert path.exists()
        raw = path.read_text()
        assert "u-w" in raw
        assert "fixed-id-for-test" in raw

    async def test_record_generates_id_when_not_provided(self, test_settings):
        repo = self._make_repo(test_settings)
        out = await repo.record(
            user_id="u-1",
            email="u@example.com",
            success=True,
        )
        assert "id" in out
        assert len(out["id"]) > 0

    async def test_record_generates_timestamp_when_not_provided(self, test_settings):
        repo = self._make_repo(test_settings)
        out = await repo.record(
            user_id="u-1",
            email="u@example.com",
            success=True,
        )
        assert "timestamp" in out
        assert len(out["timestamp"]) > 0

    async def test_record_failure_reason_preserved(self, test_settings):
        repo = self._make_repo(test_settings)
        out = await repo.record(
            user_id="u-1",
            email="u@example.com",
            success=False,
            failure_reason="invalid_password",
        )
        assert out["success"] is False
        assert out["failure_reason"] == "invalid_password"

    # ----- list_for_user -----

    async def test_list_for_user_returns_empty_for_unknown_user(self, test_settings):
        repo = self._make_repo(test_settings)
        page, total = await repo.list_for_user("nobody")
        assert page == []
        assert total == 0

    async def test_list_for_user_returns_records_newest_first(self, test_settings):
        repo = self._make_repo(test_settings)
        old = _make_entry(user_id="u-ord")
        old["id"] = "old"
        old["timestamp"] = (utcnow() - timedelta(days=2)).isoformat()
        new = _make_entry(user_id="u-ord")
        new["id"] = "new"
        new["timestamp"] = utcnow().isoformat()
        for r in (old, new):
            await repo.record(
                user_id=r["user_id"],
                email=r["email"],
                success=r["success"],
                ip_address=r["ip_address"],
                user_agent=r["user_agent"],
                failure_reason=r["failure_reason"],
                entry_id=r["id"],
                timestamp=r["timestamp"],
            )
        page, total = await repo.list_for_user("u-ord")
        assert total == 2
        assert page[0]["id"] == "new"
        assert page[1]["id"] == "old"

    async def test_list_for_user_pagination(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(5):
            record = _make_entry(user_id="u-page")
            record["id"] = f"e-{i:02d}"
            record["timestamp"] = (utcnow() + timedelta(seconds=i)).isoformat()
            await repo.record(
                user_id=record["user_id"],
                email=record["email"],
                success=record["success"],
                ip_address=record["ip_address"],
                user_agent=record["user_agent"],
                failure_reason=record["failure_reason"],
                entry_id=record["id"],
                timestamp=record["timestamp"],
            )
        page1, total1 = await repo.list_for_user("u-page", limit=2, offset=0)
        page2, total2 = await repo.list_for_user("u-page", limit=2, offset=2)
        assert total1 == 5
        assert total2 == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert {e["id"] for e in page1}.isdisjoint({e["id"] for e in page2})

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        for uid in ("u-a", "u-b"):
            record = _make_entry(user_id=uid)
            record["id"] = f"{uid}-entry"
            await repo.record(
                user_id=record["user_id"],
                email=record["email"],
                success=record["success"],
                ip_address=record["ip_address"],
                user_agent=record["user_agent"],
                failure_reason=record["failure_reason"],
                entry_id=record["id"],
                timestamp=record["timestamp"],
            )
        page, total = await repo.list_for_user("u-a")
        assert total == 1
        assert page[0]["user_id"] == "u-a"

    async def test_list_for_user_skips_corrupt_json(self, test_settings):
        repo = self._make_repo(test_settings)
        user_dir = Path(repo._user_dir("u-corrupt"))
        user_dir.mkdir(parents=True, exist_ok=True)
        (user_dir / "noise.json").write_text("not valid json {")
        # Plus a valid one
        record = _make_entry(user_id="u-corrupt")
        record["id"] = "ok-entry"
        await repo.record(
            user_id=record["user_id"],
            email=record["email"],
            success=record["success"],
            ip_address=record["ip_address"],
            user_agent=record["user_agent"],
            failure_reason=record["failure_reason"],
            entry_id=record["id"],
            timestamp=record["timestamp"],
        )
        page, total = await repo.list_for_user("u-corrupt")
        assert total == 1
        assert page[0]["id"] == "ok-entry"

    # ----- cleanup_old (was os.remove() bug — now backend-agnostic rm) -----

    async def test_cleanup_old_deletes_only_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        old = _make_entry(user_id="u-clean")
        old["id"] = "old-entry"
        old["timestamp"] = (utcnow() - timedelta(days=120)).isoformat()
        new = _make_entry(user_id="u-clean")
        new["id"] = "new-entry"
        new["timestamp"] = utcnow().isoformat()
        for r in (old, new):
            await repo.record(
                user_id=r["user_id"],
                email=r["email"],
                success=r["success"],
                ip_address=r["ip_address"],
                user_agent=r["user_agent"],
                failure_reason=r["failure_reason"],
                entry_id=r["id"],
                timestamp=r["timestamp"],
            )
        cutoff = (utcnow() - timedelta(days=90)).isoformat()
        deleted = await repo.cleanup_old("u-clean", cutoff)
        assert deleted == 1
        page, total = await repo.list_for_user("u-clean")
        assert total == 1
        assert page[0]["id"] == "new-entry"
        # The expired entry's file is gone
        assert not Path(repo._entry_path("u-clean", "old-entry")).exists()

    async def test_cleanup_old_keeps_recent(self, test_settings):
        repo = self._make_repo(test_settings)
        record = _make_entry(user_id="u-recent")
        record["id"] = "recent"
        record["timestamp"] = utcnow().isoformat()
        await repo.record(
            user_id=record["user_id"],
            email=record["email"],
            success=record["success"],
            ip_address=record["ip_address"],
            user_agent=record["user_agent"],
            failure_reason=record["failure_reason"],
            entry_id=record["id"],
            timestamp=record["timestamp"],
        )
        cutoff = (utcnow() - timedelta(days=90)).isoformat()
        deleted = await repo.cleanup_old("u-recent", cutoff)
        assert deleted == 0

    async def test_cleanup_old_uses_afs_rm_not_os_remove(self, test_settings):
        """Regression test for the pre-refactor ``os.remove()``
        bypass bug. The cleanup must use the async-fsspec
        ``rm`` (i.e. the repository's ``_delete`` method), not
        ``os.remove`` — so it works on non-``file`` backends.
        """
        repo = self._make_repo(test_settings)
        record = _make_entry(user_id="u-bug")
        record["id"] = "will-be-old"
        record["timestamp"] = (utcnow() - timedelta(days=200)).isoformat()
        await repo.record(
            user_id=record["user_id"],
            email=record["email"],
            success=record["success"],
            ip_address=record["ip_address"],
            user_agent=record["user_agent"],
            failure_reason=record["failure_reason"],
            entry_id=record["id"],
            timestamp=record["timestamp"],
        )
        # Spy on the repo's own _delete to ensure cleanup goes
        # through it (instead of os.remove which would bypass the
        # fsspec abstraction).
        from unittest.mock import patch as _patch

        with _patch.object(
            repo, "_delete", wraps=repo._delete
        ) as spy_delete:
            cutoff = (utcnow() - timedelta(days=90)).isoformat()
            deleted = await repo.cleanup_old("u-bug", cutoff)
        assert deleted == 1
        assert spy_delete.call_count == 1

    async def test_cleanup_old_returns_zero_for_unknown_user(self, test_settings):
        repo = self._make_repo(test_settings)
        cutoff = (utcnow() - timedelta(days=90)).isoformat()
        assert await repo.cleanup_old("nobody", cutoff) == 0


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileLoginHistoryRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding —
        and (unlike the pre-refactor service) honours
        ``Settings.storage_backend``.
        """
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
            repo = FileLoginHistoryRepository()
            assert Path(repo._storage_path).exists()
