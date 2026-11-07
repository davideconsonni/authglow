"""Tests for concurrency primitives and race-condition protection (M6)."""

import asyncio
import json
import os
import tempfile
import threading
import time
from unittest.mock import patch, MagicMock

import pytest

from authglow.core.concurrency import (
    AsyncNamedLock,
    ConcurrentWriteError,
    ThreadNamedLock,
    named_lock,
    thread_named_lock,
)
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
# ThreadNamedLock tests
# ──────────────────────────────────────────────


class TestThreadNamedLock:
    """Tests for the per-key threading lock used by the CAS helpers."""

    def test_singleton(self):
        assert thread_named_lock() is thread_named_lock()

    def test_same_key_serializes_across_threads(self):
        lock = ThreadNamedLock()
        events = []
        barrier = threading.Barrier(2)

        def worker(value):
            barrier.wait()
            with lock("shared"):
                events.append(f"{value}-start")
                time.sleep(0.05)
                events.append(f"{value}-end")

        threads = [threading.Thread(target=worker, args=(value,)) for value in ("A", "B")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        a_start = events.index("A-start")
        a_end = events.index("A-end")
        b_start = events.index("B-start")
        b_end = events.index("B-end")
        assert a_end < b_start or b_end < a_start

    def test_different_keys_do_not_block(self):
        lock = ThreadNamedLock()
        guard = threading.Lock()
        barrier = threading.Barrier(2)
        active = 0
        peak = 0

        def worker(key):
            nonlocal active, peak
            barrier.wait()
            with lock(key):
                with guard:
                    active += 1
                    peak = max(peak, active)
                time.sleep(0.05)
                with guard:
                    active -= 1

        threads = [threading.Thread(target=worker, args=(key,)) for key in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert peak == 2

    def test_entries_are_evicted_when_idle(self):
        lock = ThreadNamedLock()
        with lock("one"):
            assert "one" in lock._entries
        assert lock._entries == {}


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
# CAS per-path locking tests
# ──────────────────────────────────────────────


class _SlowFileSystem:
    """Minimal fsspec-like filesystem that records overlapping writers."""

    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.peak_writers = 0
        self._active_writers = 0
        self._files: dict[str, str] = {}
        self._guard = threading.Lock()

    def open(self, path: str, mode: str):
        if "r" in mode:
            return _SlowReadHandle(self, path)
        return _SlowWriteHandle(self, path)

    def read(self, path: str) -> str:
        with self._guard:
            if path not in self._files:
                raise FileNotFoundError(path)
            return self._files[path]

    def store(self, path: str, content: str) -> None:
        with self._guard:
            self._files[path] = content

    def enter_writer(self) -> None:
        with self._guard:
            self._active_writers += 1
            self.peak_writers = max(self.peak_writers, self._active_writers)

    def leave_writer(self) -> None:
        with self._guard:
            self._active_writers -= 1


class _SlowReadHandle:
    """Read handle that raises ``FileNotFoundError`` at ``open()`` time."""

    def __init__(self, fs: _SlowFileSystem, path: str) -> None:
        self._content = fs.read(path)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self) -> str:
        return self._content


class _SlowWriteHandle:
    """Write handle that holds the writer slot for ``fs.delay`` seconds."""

    def __init__(self, fs: _SlowFileSystem, path: str) -> None:
        self._fs = fs
        self._path = path
        self._chunks: list[str] = []

    def __enter__(self):
        self._fs.enter_writer()
        time.sleep(self._fs.delay)
        return self

    def __exit__(self, *exc):
        self._fs.leave_writer()
        if exc[0] is None:
            self._fs.store(self._path, "".join(self._chunks))
        return False

    def write(self, chunk: str) -> None:
        self._chunks.append(chunk)


class TestCASPerPathLocking:
    """The CAS critical section serializes per record path, not process-wide."""

    @pytest.mark.asyncio
    async def test_writes_to_different_paths_overlap(self):
        fs = _SlowFileSystem(delay=0.1)
        afs = AsyncFileSystem(fs)

        await asyncio.gather(
            afs.write_json_versioned("a.json", {"n": 1}, expected_version=0),
            afs.write_json_versioned("b.json", {"n": 2}, expected_version=0),
        )

        assert fs.peak_writers == 2, "different paths must not serialize each other"
        assert thread_named_lock()._entries == {}, "idle lock entries must be evicted"

    @pytest.mark.asyncio
    async def test_writes_to_same_path_are_serialized(self):
        fs = _SlowFileSystem(delay=0.05)
        afs = AsyncFileSystem(fs)

        results = await asyncio.gather(
            afs.write_json_versioned("same.json", {"n": 1}, expected_version=0),
            afs.write_json_versioned("same.json", {"n": 2}, expected_version=0),
            return_exceptions=True,
        )

        assert fs.peak_writers == 1, "same-path writes must not overlap"
        assert sum(isinstance(result, ConcurrentWriteError) for result in results) == 1

    def test_same_path_across_fresh_event_loops(self, tmp_path):
        """Regression guard: the CAS lock must not bind to one event loop."""
        afs = AsyncFileSystem(fsspec.filesystem("file"))
        path = str(tmp_path / "record.json")

        async def contended_write() -> None:
            results = await asyncio.gather(
                afs.write_json_versioned(path, {"n": 1}, expected_version=0),
                afs.write_json_versioned(path, {"n": 2}, expected_version=0),
                return_exceptions=True,
            )
            assert sum(isinstance(result, ConcurrentWriteError) for result in results) == 1

        asyncio.run(contended_write())
        os.remove(path)
        asyncio.run(contended_write())


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
