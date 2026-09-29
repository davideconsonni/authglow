"""Regression tests for ``FileDeviceAuthorizationRepository``.

Pins the fix for the listing bug: ``list_all`` / ``delete_expired`` used
to skip every file whose basename started with ``_`` to dodge the
``_by_user_code`` index directory. ``device_code`` is base64-url, so a
real authorization could start with ``_`` and was then invisible to
every listing and never cleaned up. The ``*.json`` glob already matches
direct children only, so the index directory is excluded without any
basename filter.
"""

from datetime import timedelta

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
