"""Unit tests for the three File-backed MFA repositories.

Covers ``FileBackupCodeRepository``, ``FileBackupCodeAttemptRepository``
and ``FileTrustedDeviceRepository``. The service-level behaviour
(``named_lock``, brute-force lockout policy, ``last_used``
update-with-CAS-retry) is exercised by ``tests/unit/test_mfa.py`` and
``tests/integration/test_mfa_api.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and a couple of edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.mfa import BackupCodeAttempt, BackupCodes, TrustedDevice
from authglow.repositories.file.mfa import (
    FileBackupCodeAttemptRepository,
    FileBackupCodeRepository,
    FileTrustedDeviceRepository,
)
from authglow.repositories.protocols import (
    BackupCodeAttemptRepository,
    BackupCodeRepository,
    TrustedDeviceRepository,
)


def _make_backup_codes(user_id: str = "user-1", n: int = 3) -> BackupCodes:
    return BackupCodes(
        user_id=user_id,
        codes=[f"hash-{i}" for i in range(n)],
        used_count=0,
    )


def _make_attempt(user_id: str = "user-1", failed: int = 1) -> BackupCodeAttempt:
    return BackupCodeAttempt(
        user_id=user_id,
        failed_attempts=failed,
        last_attempt_at=utcnow(),
    )


def _make_device(
    user_id: str = "user-1",
    fp: str = "fp-1",
    *,
    expires_in_days: int = 30,
    name: str | None = "Test Device",
) -> TrustedDevice:
    return TrustedDevice(
        user_id=user_id,
        device_fingerprint=fp,
        name=name,
        expires_at=utcnow() + timedelta(days=expires_in_days),
    )


# ---------------------------------------------------------------------------
# FileBackupCodeRepository
# ---------------------------------------------------------------------------


class TestFileBackupCodeRepository:
    def _make_repo(self, test_settings) -> FileBackupCodeRepository:
        return FileBackupCodeRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "mfa/backup_codes"
        assert Path(repo._storage_path).name == "backup_codes"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, BackupCodeRepository)

    async def test_save_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        codes = _make_backup_codes(user_id="u-roundtrip")
        await repo.save(codes)
        loaded = await repo.get("u-roundtrip")
        assert loaded is not None
        assert loaded.user_id == "u-roundtrip"
        assert loaded.codes == codes.codes

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nonexistent") is None

    async def test_save_overwrites(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_backup_codes(user_id="u-ow", n=3))
        await repo.save(_make_backup_codes(user_id="u-ow", n=5))
        loaded = await repo.get("u-ow")
        assert loaded is not None
        assert len(loaded.codes) == 5

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_backup_codes(user_id="u-del"))
        await repo.delete("u-del")
        assert await repo.get("u-del") is None

    async def test_delete_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.delete("u-missing")
        assert await repo.get("u-missing") is None

    async def test_use_code_removes_and_increments(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_backup_codes(user_id="u-use", n=3))
        result = await repo.use_code("u-use", "hash-1")
        assert result is True
        loaded = await repo.get("u-use")
        assert loaded is not None
        assert "hash-1" not in loaded.codes
        assert loaded.used_count == 1

    async def test_use_code_returns_false_for_missing_hash(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_backup_codes(user_id="u-use-miss", n=2))
        result = await repo.use_code("u-use-miss", "hash-NONEXISTENT")
        assert result is False
        loaded = await repo.get("u-use-miss")
        assert loaded is not None
        assert loaded.used_count == 0

    async def test_use_code_returns_false_for_missing_user(self, test_settings):
        repo = self._make_repo(test_settings)
        result = await repo.use_code("u-noexist", "hash-x")
        assert result is False

    async def test_corrupt_json_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        path = Path(repo._path_for("u-corrupt"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        assert await repo.get("u-corrupt") is None


# ---------------------------------------------------------------------------
# FileBackupCodeAttemptRepository
# ---------------------------------------------------------------------------


class TestFileBackupCodeAttemptRepository:
    def _make_repo(self, test_settings) -> FileBackupCodeAttemptRepository:
        return FileBackupCodeAttemptRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "mfa/backup_code_attempts"
        assert Path(repo._storage_path).name == "backup_code_attempts"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, BackupCodeAttemptRepository)

    async def test_save_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        a = _make_attempt(user_id="u-att", failed=3)
        await repo.save(a)
        loaded = await repo.get("u-att")
        assert loaded is not None
        assert loaded.failed_attempts == 3
        assert loaded.user_id == "u-att"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nonexistent") is None

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(_make_attempt(user_id="u-reset"))
        await repo.delete("u-reset")
        assert await repo.get("u-reset") is None

    async def test_delete_is_idempotent(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.delete("u-missing")


# ---------------------------------------------------------------------------
# FileTrustedDeviceRepository
# ---------------------------------------------------------------------------


class TestFileTrustedDeviceRepository:
    def _make_repo(self, test_settings) -> FileTrustedDeviceRepository:
        return FileTrustedDeviceRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "mfa/trusted_devices"
        assert Path(repo._storage_path).name == "trusted_devices"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, TrustedDeviceRepository)

    async def test_add_and_get_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        device = _make_device(user_id="u-add", fp="fp-add")
        await repo.add(device)
        loaded = await repo.get(device.id)
        assert loaded is not None
        assert loaded.device_fingerprint == "fp-add"
        assert loaded.user_id == "u-add"

    async def test_get_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nonexistent-id") is None

    async def test_update_persists_last_used(self, test_settings):
        repo = self._make_repo(test_settings)
        device = _make_device(user_id="u-upd", fp="fp-upd")
        await repo.add(device)
        device.last_used = utcnow() + timedelta(hours=1)
        await repo.update(device)
        loaded = await repo.get(device.id)
        assert loaded is not None
        assert loaded.last_used == device.last_used

    async def test_update_missing_raises(self, test_settings):
        repo = self._make_repo(test_settings)
        device = _make_device(user_id="u-upd-miss", fp="fp-x")
        with patch("builtins.print"):  # silence traceback noise
            pass
        import pytest

        with pytest.raises(FileNotFoundError):
            await repo.update(device)

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        device = _make_device(user_id="u-del-td", fp="fp-del")
        await repo.add(device)
        result = await repo.delete(device.id)
        assert result is True
        assert await repo.get(device.id) is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nonexistent-id") is False

    async def test_list_for_user_filters_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        valid = _make_device(user_id="u-list", fp="fp-v", expires_in_days=30)
        expired = _make_device(user_id="u-list", fp="fp-e", expires_in_days=-1)
        await repo.add(valid)
        await repo.add(expired)
        result = await repo.list_for_user("u-list")
        assert len(result) == 1
        assert result[0].device_fingerprint == "fp-v"

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add(_make_device(user_id="u-a", fp="fp-1"))
        await repo.add(_make_device(user_id="u-b", fp="fp-2"))
        result = await repo.list_for_user("u-a")
        assert len(result) == 1
        assert result[0].user_id == "u-a"

    async def test_list_for_user_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list_for_user("nonexistent") == []

    async def test_find_trusted_returns_match(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add(_make_device(user_id="u-find", fp="fp-target"))
        await repo.add(_make_device(user_id="u-find", fp="fp-other"))
        result = await repo.find_trusted("u-find", "fp-target")
        assert result is not None
        assert result.device_fingerprint == "fp-target"

    async def test_find_trusted_skips_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add(_make_device(user_id="u-find-exp", fp="fp-x", expires_in_days=-1))
        result = await repo.find_trusted("u-find-exp", "fp-x")
        assert result is None

    async def test_find_trusted_skips_other_user(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.add(_make_device(user_id="u-other", fp="fp-shared"))
        result = await repo.find_trusted("u-me", "fp-shared")
        assert result is None

    async def test_find_trusted_returns_none_when_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        result = await repo.find_trusted("nobody", "no-fp")
        assert result is None

    async def test_cleanup_expired_deletes_only_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        valid = _make_device(user_id="u-clean", fp="fp-v", expires_in_days=30)
        expired1 = _make_device(user_id="u-clean", fp="fp-e1", expires_in_days=-1)
        expired2 = _make_device(user_id="u-clean", fp="fp-e2", expires_in_days=-2)
        await repo.add(valid)
        await repo.add(expired1)
        await repo.add(expired2)
        deleted = await repo.cleanup_expired()
        assert deleted == 2
        assert await repo.get(valid.id) is not None
        assert await repo.get(expired1.id) is None
        assert await repo.get(expired2.id) is None

    async def test_cleanup_expired_zero_when_nothing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.cleanup_expired() == 0


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileMFARepositoriesWithPatchedSettings:
    def test_all_three_construct_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructors resolve
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
            bc_repo = FileBackupCodeRepository()
            at_repo = FileBackupCodeAttemptRepository()
            td_repo = FileTrustedDeviceRepository()
            assert Path(bc_repo._storage_path).exists()
            assert Path(at_repo._storage_path).exists()
            assert Path(td_repo._storage_path).exists()
