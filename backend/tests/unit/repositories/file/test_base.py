"""Smoke tests for ``BaseFileRepository`` — the scaffold shared by all
``File<Entity>Repository`` classes.

These tests cover the I/O primitives that every concrete file-backed
repository will rely on: path building, JSON read/write, versioned
JSON read/write (CAS), file existence, deletion, and glob. The
entity-specific subclasses add their own tests on top.
"""

import os

import pytest

from authglow.core.concurrency import ConcurrentWriteError
from authglow.repositories.file.base import BaseFileRepository


class _TestRepository(BaseFileRepository):
    """Minimal concrete subclass used to exercise BaseFileRepository."""

    _subdir = "_test_base_repo"


@pytest.fixture
def repo(test_settings):
    """A fresh BaseFileRepository instance pointing at the test temp dir."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("authglow.repositories.file.base.get_settings", lambda: test_settings)
        return _TestRepository()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_subdir_is_required(self, test_settings):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("authglow.repositories.file.base.get_settings", lambda: test_settings)
            with pytest.raises(ValueError, match="must set _subdir"):
                BaseFileRepository()

    def test_subdir_override_via_constructor(self, test_settings):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("authglow.repositories.file.base.get_settings", lambda: test_settings)
            repo = BaseFileRepository(subdir="_override_subdir")
            assert repo._subdir == "_override_subdir"
            assert repo._storage_path.endswith("_override_subdir")

    def test_storage_path_is_under_settings_root(self, repo, test_settings):
        assert repo._storage_path == f"{test_settings.storage_path}/_test_base_repo"

    def test_extra_dirs_created_on_init(self, test_settings, tmp_path):
        storage_path = str(tmp_path / "extra_dirs_test")
        os.makedirs(storage_path, exist_ok=True)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("authglow.repositories.file.base.get_settings", lambda: test_settings)
            mp.setattr(test_settings, "storage_path", storage_path)
            BaseFileRepository(subdir="_test_extra", extra_dirs=("a", "b/c"))

        assert os.path.isdir(f"{storage_path}/_test_extra/a")
        assert os.path.isdir(f"{storage_path}/_test_extra/b/c")

    def test_filesystem_is_local_when_backend_is_file(self, repo):
        assert repo._settings.storage_backend == "file"
        assert repo._filesystem is not None
        assert repo._afs is not None
        assert repo._lock is not None


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


class TestPathHelpers:
    def test_path_strips_leading_slash(self, repo):
        assert repo._path("foo.json") == repo._path("/foo.json")

    def test_path_supports_nested_filenames(self, repo):
        assert repo._path("a/b/c.json") == f"{repo._storage_path}/a/b/c.json"

    @pytest.mark.asyncio
    async def test_ensure_parent_creates_intermediate_directories(self, repo):
        nested = repo._path("a/b/c.json")
        assert not os.path.exists(os.path.dirname(nested))
        await repo._ensure_parent(nested)
        assert os.path.isdir(os.path.dirname(nested))


# ---------------------------------------------------------------------------
# JSON read / write
# ---------------------------------------------------------------------------


class TestJsonIO:
    @pytest.mark.asyncio
    async def test_write_and_read_json_roundtrip(self, repo):
        path = repo._path("hello.json")
        payload = {"hello": "world", "n": 42}
        await repo._write_json(path, payload)
        loaded = await repo._read_json(path)
        assert loaded == payload

    @pytest.mark.asyncio
    async def test_read_missing_returns_none(self, repo):
        assert await repo._read_json(repo._path("absent.json")) is None

    @pytest.mark.asyncio
    async def test_read_corrupt_returns_none(self, repo):
        path = repo._path("corrupt.json")
        with open(path, "w") as f:
            f.write("{not valid json")
        assert await repo._read_json(path) is None

    @pytest.mark.asyncio
    async def test_write_json_creates_parent_dirs(self, repo):
        path = repo._path("deep/nested/file.json")
        await repo._write_json(path, {"x": 1})
        assert os.path.isfile(path)


# ---------------------------------------------------------------------------
# JSON versioned (CAS) read / write
# ---------------------------------------------------------------------------


class TestJsonVersionedIO:
    @pytest.mark.asyncio
    async def test_first_write_has_version_zero(self, repo):
        path = repo._path("v.json")
        data, version = await repo._read_json_versioned(path)
        assert data is None
        assert version == 0

    @pytest.mark.asyncio
    async def test_version_increments_on_each_write(self, repo):
        path = repo._path("v.json")
        await repo._write_json_versioned(path, {"n": 1}, expected_version=0)
        data, version = await repo._read_json_versioned(path)
        assert version == 1
        assert data == {"n": 1}

        await repo._write_json_versioned(path, {"n": 2}, expected_version=1)
        data, version = await repo._read_json_versioned(path)
        assert version == 2
        assert data == {"n": 2}

    @pytest.mark.asyncio
    async def test_concurrent_write_raises_on_version_mismatch(self, repo):
        path = repo._path("v.json")
        await repo._write_json_versioned(path, {"n": 1}, expected_version=0)

        with pytest.raises(ConcurrentWriteError):
            await repo._write_json_versioned(path, {"n": 2}, expected_version=99)


# ---------------------------------------------------------------------------
# Atomic write (tmp + rename)
# ---------------------------------------------------------------------------


class TestAtomicWrite:
    @pytest.mark.asyncio
    async def test_atomic_write_roundtrip(self, repo):
        path = repo._path("atomic.json")
        await repo._write_json_atomic(path, {"x": 1})
        assert await repo._read_json(path) == {"x": 1}

    @pytest.mark.asyncio
    async def test_atomic_write_does_not_leave_tmp(self, repo):
        path = repo._path("atomic2.json")
        await repo._write_json_atomic(path, {"x": 2})
        assert not os.path.exists(path + ".tmp")
        assert os.path.exists(path)

    @pytest.mark.asyncio
    async def test_atomic_write_overwrites_existing(self, repo):
        path = repo._path("atomic3.json")
        await repo._write_json_atomic(path, {"n": 1})
        await repo._write_json_atomic(path, {"n": 2})
        assert await repo._read_json(path) == {"n": 2}
        assert not os.path.exists(path + ".tmp")

    @pytest.mark.asyncio
    async def test_atomic_write_creates_parent_dirs(self, repo):
        path = repo._path("deep/nested/atomic.json")
        await repo._write_json_atomic(path, {"y": 1})
        assert os.path.isfile(path)
        assert not os.path.exists(path + ".tmp")


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


class TestFilesystemHelpers:
    @pytest.mark.asyncio
    async def test_exists_true_after_write(self, repo):
        path = repo._path("present.json")
        await repo._write_json(path, {"a": 1})
        assert await repo._exists(path) is True

    @pytest.mark.asyncio
    async def test_exists_false_when_missing(self, repo):
        assert await repo._exists(repo._path("absent.json")) is False

    @pytest.mark.asyncio
    async def test_delete_returns_true_when_present(self, repo):
        path = repo._path("deleteme.json")
        await repo._write_json(path, {"a": 1})
        assert await repo._delete(path) is True
        assert await repo._exists(path) is False

    @pytest.mark.asyncio
    async def test_delete_returns_false_when_missing(self, repo):
        assert await repo._delete(repo._path("absent.json")) is False

    @pytest.mark.asyncio
    async def test_glob_returns_matching_files(self, repo):
        await repo._write_json(repo._path("a.json"), {})
        await repo._write_json(repo._path("b.json"), {})
        await repo._write_json(repo._path("c.txt"), "")
        files = await repo._glob(f"{repo._storage_path}/*.json")
        assert len(files) == 2
        assert all(f.endswith(".json") for f in files)


# ---------------------------------------------------------------------------
# Module-level: Protocol importability
# ---------------------------------------------------------------------------


class TestProtocolsImportable:
    """Sanity check that every Protocol declared in
    ``authglow.repositories.protocols`` can be imported via the
    package's public ``__init__``."""

    def test_all_protocols_importable_from_package(self):
        from authglow.repositories import (
            AdminActionRepository,
            APIKeyRepository,
            AuthorizationCodeRepository,
            BackupCodeAttemptRepository,
            BackupCodeRepository,
            CSRFTokenRepository,
            EmailIndexRepository,
            EmailVerificationRepository,
            EntityAlreadyExistsError,
            EntityNotFoundError,
            FederatedIdentityRepository,
            FederationProviderRepository,
            LoginHistoryRepository,
            OAuth2ClientRepository,
            OAuth2ConsentRepository,
            PasskeyRepository,
            PasswordResetRepository,
            PermissionRepository,
            RefreshTokenRepository,
            RoleRepository,
            SecurityEventRepository,
            SessionRepository,
            TrustedDeviceRepository,
            UserPreferencesRepository,
            UserRepository,
            WebAuthnChallengeRepository,
        )

        assert EntityNotFoundError is not None
        assert EntityAlreadyExistsError is not None
        for proto in (
            APIKeyRepository,
            AdminActionRepository,
            AuthorizationCodeRepository,
            BackupCodeAttemptRepository,
            BackupCodeRepository,
            CSRFTokenRepository,
            EmailIndexRepository,
            EmailVerificationRepository,
            FederatedIdentityRepository,
            FederationProviderRepository,
            LoginHistoryRepository,
            OAuth2ClientRepository,
            OAuth2ConsentRepository,
            PasswordResetRepository,
            PasskeyRepository,
            PermissionRepository,
            RefreshTokenRepository,
            RoleRepository,
            SecurityEventRepository,
            SessionRepository,
            TrustedDeviceRepository,
            UserPreferencesRepository,
            UserRepository,
            WebAuthnChallengeRepository,
        ):
            assert isinstance(proto, type)
