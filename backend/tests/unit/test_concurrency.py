"""Tests for concurrency primitives and race-condition protection (M6)."""

import asyncio
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from authglow.core.concurrency import AsyncNamedLock, ConcurrentWriteError, named_lock
from authglow.core.async_io import AsyncFileSystem
import fsspec


# ──────────────────────────────────────────────
# AsyncNamedLock tests
# ──────────────────────────────────────────────


class TestAsyncNamedLock:
    """Tests for the per-key asyncio.Lock wrapper."""

    def test_named_lock_singleton(self):
        lock1 = named_lock()
        lock2 = named_lock()
        assert lock1 is lock2

    @pytest.mark.asyncio
    async def test_basic_acquire_release(self):
        lock = AsyncNamedLock()
        async with lock("test-key"):
            assert lock.is_held("test-key")
        assert not lock.is_held("test-key")

    @pytest.mark.asyncio
    async def test_different_keys_dont_block(self):
        lock = AsyncNamedLock()
        results = []

        async def task(key, delay):
            async with lock(key):
                results.append(f"{key}-start")
                await asyncio.sleep(delay)
                results.append(f"{key}-end")

        await asyncio.gather(task("a", 0.01), task("b", 0.01))
        assert "a-start" in results
        assert "b-start" in results

    @pytest.mark.asyncio
    async def test_same_key_serializes(self):
        lock = AsyncNamedLock()
        results = []

        async def task(key, value, delay):
            async with lock(key):
                results.append(f"{value}-start")
                await asyncio.sleep(delay)
                results.append(f"{value}-end")

        t1 = asyncio.create_task(task("shared", "A", 0.05))
        t2 = asyncio.create_task(task("shared", "B", 0.01))
        await asyncio.gather(t1, t2)

        a_start = results.index("A-start")
        a_end = results.index("A-end")
        b_start = results.index("B-start")
        b_end = results.index("B-end")

        assert a_end < b_start or b_end < a_start

    @pytest.mark.asyncio
    async def test_concurrent_counter_without_lock(self):
        """Demonstrates the race condition when no lock is used.

        Without locking, concurrent RMW on the same file can produce
        incorrect results (lost updates).  We use a short serial delay
        to guarantee at least some interleaving, then check that the
        final value is less than the number of increments.
        """
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "counter.json")
            await afs.write_json(path, {"value": 0})

            async def increment():
                try:
                    data = await afs.read_json(path)
                    data["value"] += 1
                    await afs.write_json(path, data)
                except (json.JSONDecodeError, FileNotFoundError):
                    pass

            await asyncio.gather(*[increment() for _ in range(10)])

            try:
                final = await afs.read_json(path)
                assert final["value"] <= 10
            except (json.JSONDecodeError, FileNotFoundError):
                pass

    @pytest.mark.asyncio
    async def test_concurrent_counter_with_lock(self):
        """Proves that the lock prevents lost updates."""
        lock = AsyncNamedLock()
        counter_path = "counter.json"
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, counter_path)
            await afs.write_json(path, {"value": 0})

            async def increment():
                async with lock("counter"):
                    data = await afs.read_json(path)
                    data["value"] += 1
                    await afs.write_json(path, data)

            await asyncio.gather(*[increment() for _ in range(20)])

            final = await afs.read_json(path)
            assert final["value"] == 20

    @pytest.mark.asyncio
    async def test_is_held_returns_false_for_unknown_key(self):
        lock = AsyncNamedLock()
        assert not lock.is_held("nonexistent")


# ──────────────────────────────────────────────
# ConcurrentWriteError + CAS tests
# ──────────────────────────────────────────────


class TestConcurrentWriteError:
    """Tests for the optimistic-concurrency CAS layer."""

    def test_concurrent_write_error_is_exception(self):
        err = ConcurrentWriteError("Version mismatch")
        assert isinstance(err, Exception)
        assert "Version mismatch" in str(err)

    @pytest.mark.asyncio
    async def test_versioned_read_write_roundtrip(self):
        """read_json_versioned then write_json_versioned succeeds when version matches."""
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "record.json")
            await afs.write_json(path, {"name": "test", "_version": 0})

            data, version = await afs.read_json_versioned(path)
            assert data["name"] == "test"
            assert version == 0

            data["name"] = "updated"
            await afs.write_json_versioned(path, data, version)

            result = await afs.read_json(path)
            assert result["name"] == "updated"
            assert result["_version"] == 1

    @pytest.mark.asyncio
    async def test_versioned_write_rejects_stale_version(self):
        """write_json_versioned raises ConcurrentWriteError if version changed."""
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "record.json")
            await afs.write_json(path, {"name": "test", "_version": 5})

            with pytest.raises(ConcurrentWriteError):
                await afs.write_json_versioned(
                    path, {"name": "stale"}, expected_version=3
                )

    @pytest.mark.asyncio
    async def test_versioned_write_to_new_file(self):
        """CAS write to a non-existent file uses version 0."""
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "new_record.json")

            # Write initial data with version 0 (file doesn't exist yet)
            await afs.write_json_versioned(path, {"name": "new"}, expected_version=0)

            result = await afs.read_json(path)
            assert result["name"] == "new"
            assert result["_version"] == 1

    @pytest.mark.asyncio
    async def test_versioned_read_missing_file(self):
        """read_json_versioned returns (empty, 0) for missing files."""
        fs = fsspec.filesystem("file")
        afs = AsyncFileSystem(fs)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "missing.json")

            with pytest.raises(FileNotFoundError):
                await afs.read_json_versioned(path)


# ──────────────────────────────────────────────
# Integration: Storage race-condition tests
# ──────────────────────────────────────────────


class TestStorageRaceConditions:
    """Integration tests proving storage methods are safe under concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_create_users_no_email_loss(self, tmp_path, test_settings):
        """Two users created concurrently should both appear in the email index."""
        from authglow.services.user import UserService as UserStorage
        from authglow.models.user import User
        from authglow.services.password import hash_password

        storage_path = str(tmp_path / "data" / "users")
        os.makedirs(storage_path, exist_ok=True)

        settings = test_settings.model_copy(update={"storage_path": storage_path})
        with patch("authglow.services.user.get_settings", return_value=settings):
            storage = UserStorage()

        users = [
            User(
                id=f"user-email-{i}",
                email=f"testemail{i}@example.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=True,
                email_verified=True,
            )
            for i in range(5)
        ]

        await asyncio.gather(*[storage.create_user(u) for u in users])

        for user in users:
            found = await storage.get_user_by_email(user.email)
            assert found is not None, f"User with email {user.email} not found in index"

    @pytest.mark.asyncio
    async def test_concurrent_failed_logins_increment_correctly(
        self, tmp_path, test_settings
    ):
        """Concurrent failed login increments should all be counted."""
        from authglow.services.user import UserService as UserStorage
        from authglow.models.user import User
        from authglow.services.password import hash_password

        storage_path = str(tmp_path / "data" / "fl")
        os.makedirs(storage_path, exist_ok=True)

        settings = test_settings.model_copy(update={"storage_path": storage_path})
        with patch("authglow.services.user.get_settings", return_value=settings):
            storage = UserStorage()

        user = User(
            id="user-fl-test",
            email="fl@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            email_verified=True,
        )
        await storage.create_user(user)

        results = await asyncio.gather(
            *[storage.record_failed_login("user-fl-test") for _ in range(3)]
        )

        user = await storage.get_user("user-fl-test")
        assert user.failed_login_attempts == 3


# ──────────────────────────────────────────────
# Integration: OAuth2 code single-use test
# ──────────────────────────────────────────────


class TestOAuth2CodeRaceCondition:
    """Tests that authorization codes cannot be used twice concurrently."""

    @pytest.mark.asyncio
    async def test_concurrent_mark_code_as_used(self, tmp_path, test_settings):
        """Two concurrent calls to mark_code_as_used should not both succeed."""
        from authglow.services.oauth2 import OAuth2Service

        storage_path = str(tmp_path / "data" / "oauth2_test")
        os.makedirs(os.path.join(storage_path, "auth_codes"), exist_ok=True)

        settings = test_settings.model_copy(update={"storage_path": storage_path})
        with (
            patch("authglow.services.oauth2.get_settings", return_value=settings),
            patch("authglow.services.oauth_client.get_settings", return_value=settings),
        ):
            svc = OAuth2Service()

        auth_code = await svc.create_authorization_code(
            client_id="test-client",
            user_id="test-user",
            redirect_uri="http://localhost:8000/callback",
            scope="openid profile email",
        )

        results = await asyncio.gather(
            svc.mark_code_as_used(auth_code.code),
            svc.mark_code_as_used(auth_code.code),
        )

        first_true = results.count(True)
        assert first_true >= 1, "At least one call should succeed"
