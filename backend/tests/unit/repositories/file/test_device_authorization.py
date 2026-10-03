"""Regression tests for ``FileDeviceAuthorizationRepository``.

Pins the fix for the listing bug: ``list_all`` / ``delete_expired`` used
to skip every file whose basename started with ``_`` to dodge the
``_by_user_code`` index directory. ``device_code`` is base64-url, so a
real authorization could start with ``_`` and was then invisible to
every listing and never cleaned up. The ``*.json`` glob already matches
direct children only, so the index directory is excluded without any
basename filter.
"""

import json
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.token import DeviceAuthorization
from authglow.repositories.file.device_authorization import (
    FileDeviceAuthorizationRepository,
)


def _auth(device_code: str, user_code: str, *, expires_in: int = 600) -> DeviceAuthorization:
    return DeviceAuthorization(
        device_code=device_code,
        user_code=user_code,
        client_id="client-1",
        scope="read",
        verification_uri="https://verify.example",
        expires_at=utcnow() + timedelta(seconds=expires_in),
        status="pending",
    )


class TestDeviceCodeListingRegression:
    def _make_repo(self, test_settings) -> FileDeviceAuthorizationRepository:
        return FileDeviceAuthorizationRepository(settings=test_settings)

    async def test_list_all_includes_underscore_device_code(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("_leading-underscore-code", "AAAA-1111"))
        listed = await repo.list_all()
        assert [a.device_code for a in listed] == ["_leading-underscore-code"]

    async def test_delete_expired_removes_underscore_device_code(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("_expired-code", "BBBB-2222", expires_in=-1))
        assert await repo.delete_expired() == 1
        assert await repo.get_by_device_code("_expired-code") is None

    async def test_list_all_excludes_index_directory(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-a", "CCCC-3333"))
        await repo.create(_auth("code-b", "DDDD-4444"))
        listed = await repo.list_all()
        assert {a.device_code for a in listed} == {"code-a", "code-b"}
        assert len(listed) == 2


class TestDeviceAuthorizationLookup:
    """Lookup / update / delete lifecycle for the device repository."""

    def _make_repo(self, test_settings) -> FileDeviceAuthorizationRepository:
        return FileDeviceAuthorizationRepository(settings=test_settings)

    async def test_get_by_device_code_round_trip(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-get", "GET-0001"))
        auth = await repo.get_by_device_code("code-get")
        assert auth is not None
        assert auth.device_code == "code-get"
        assert auth.status == "pending"

    async def test_get_by_device_code_missing_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_device_code("nope") is None

    async def test_get_by_device_code_marks_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-old", "OLD-0001", expires_in=-1))
        auth = await repo.get_by_device_code("code-old")
        assert auth is not None
        assert auth.status == "expired"

    async def test_get_by_device_code_corrupt_json_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        Path(repo._path_for("code-corrupt")).write_text("not json {")
        assert await repo.get_by_device_code("code-corrupt") is None

    async def test_get_by_device_code_read_error_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-readerr", "ERR-0001"))
        with patch.object(repo, "_read_json", side_effect=ValueError("boom")):
            assert await repo.get_by_device_code("code-readerr") is None

    async def test_get_by_device_code_invalid_model_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        Path(repo._path_for("code-invalid")).write_text(json.dumps({"device_code": "code-invalid"}))
        assert await repo.get_by_device_code("code-invalid") is None

    async def test_get_by_user_code_round_trip(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-uc", "UC-0001"))
        auth = await repo.get_by_user_code("UC-0001")
        assert auth is not None
        assert auth.device_code == "code-uc"

    async def test_get_by_user_code_missing_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_user_code("NOPE") is None

    async def test_get_by_user_code_index_without_device_code(self, test_settings):
        repo = self._make_repo(test_settings)
        index_path = Path(repo._path_for_user_code("UC-EMPTY"))
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text(json.dumps({"foo": 1}))
        assert await repo.get_by_user_code("UC-EMPTY") is None

    async def test_get_by_user_code_empty_index_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        index_path = Path(repo._path_for_user_code("UC-CORRUPT"))
        index_path.parent.mkdir(parents=True, exist_ok=True)
        index_path.write_text("not json {")
        assert await repo.get_by_user_code("UC-CORRUPT") is None

    async def test_get_by_user_code_read_error_returns_none(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-ucerr", "UC-0002"))
        with patch.object(repo, "_read_json", side_effect=TypeError("boom")):
            assert await repo.get_by_user_code("UC-0002") is None

    async def test_update_persists_new_status(self, test_settings):
        repo = self._make_repo(test_settings)
        auth = _auth("code-upd", "UPD-0001")
        await repo.create(auth)
        auth.status = "approved"
        await repo.update(auth)
        reloaded = await repo.get_by_device_code("code-upd")
        assert reloaded is not None
        assert reloaded.status == "approved"

    async def test_delete_removes_both_indices(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-del", "DEL-0001"))
        await repo.delete("code-del")
        assert await repo.get_by_device_code("code-del") is None
        assert await repo.get_by_user_code("DEL-0001") is None
        assert not await repo._exists(repo._path_for_user_code("DEL-0001"))

    async def test_delete_unknown_is_noop(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.delete("nope")  # must not raise


class TestDeviceAuthorizationBulkEdges:
    """Corruption / error tolerance of the glob-based bulk operations."""

    def _make_repo(self, test_settings) -> FileDeviceAuthorizationRepository:
        return FileDeviceAuthorizationRepository(settings=test_settings)

    async def test_delete_expired_skips_corrupt_entries(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-exp", "EXP-0001", expires_in=-1))
        Path(repo._path_for("code-noise")).write_text("not json {")
        Path(repo._path_for("code-badshape")).write_text(
            json.dumps({"device_code": "code-badshape"})
        )
        assert await repo.delete_expired() == 1

    async def test_delete_expired_read_error_is_skipped(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-exp2", "EXP-0002", expires_in=-1))
        with patch.object(repo, "_read_json", side_effect=ValueError("boom")):
            assert await repo.delete_expired() == 0

    async def test_list_all_skips_corrupt_entries(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-good", "GOOD-0001"))
        Path(repo._path_for("code-noise2")).write_text("not json {")
        Path(repo._path_for("code-badmodel")).write_text(
            json.dumps({"device_code": "code-badmodel"})
        )
        listed = await repo.list_all()
        assert [a.device_code for a in listed] == ["code-good"]

    async def test_list_all_read_error_is_skipped(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-good2", "GOOD-0002"))
        with patch.object(repo, "_read_json", side_effect=ValueError("boom")):
            assert await repo.list_all() == []

    async def test_list_all_status_filter(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_auth("code-pending", "PEND-0001"))
        await repo.create(_auth("code-expired", "EXPD-0001", expires_in=-1))
        expired = await repo.list_all(status_filter="expired")
        assert [a.device_code for a in expired] == ["code-expired"]
        pending = await repo.list_all(status_filter="pending")
        assert [a.device_code for a in pending] == ["code-pending"]
