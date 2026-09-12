"""Unit tests for the FilePushedAuthorizationRequestRepository (OA-501).

Covers the File layout, the get policy (absent / used / expired →
``None``), the single-use CAS (``mark_used``), and the Protocol
conformance already parametrised in ``test_protocols.py``.
"""

from datetime import timedelta

from authglow.core.datetime import utcnow
from authglow.models.par import PushedAuthorizationRequest
from authglow.repositories.file.par import (
    FilePushedAuthorizationRequestRepository,
)
from authglow.repositories.protocols import PushedAuthorizationRequestRepository


def _make_repo(test_settings) -> FilePushedAuthorizationRequestRepository:
    return FilePushedAuthorizationRequestRepository(settings=test_settings)


def _make_request(**overrides) -> PushedAuthorizationRequest:
    base = {
        "client_id": "client-1",
        "redirect_uri": "https://example.com/cb",
        "scope": "openid read",
        "expires_at": utcnow() + timedelta(seconds=90),
    }
    base.update(overrides)
    return PushedAuthorizationRequest(**base)


class TestFilePARRepositoryInit:
    def test_subdir(self, test_settings):
        assert FilePushedAuthorizationRequestRepository._subdir == "par_requests"

    def test_satisfies_protocol(self, test_settings):
        assert isinstance(_make_repo(test_settings), PushedAuthorizationRequestRepository)


class TestFilePARRepositoryCreateGet:
    async def test_round_trip(self, test_settings):
        repo = _make_repo(test_settings)
        req = _make_request(state="s1", nonce="n1")
        await repo.create(req)
        fetched = await repo.get_by_request_id(req.request_id)
        assert fetched is not None
        assert fetched.client_id == "client-1"
        assert fetched.state == "s1"
        assert fetched.nonce == "n1"
        assert fetched.request_uri.endswith(req.request_id)

    async def test_missing_returns_none(self, test_settings):
        assert await _make_repo(test_settings).get_by_request_id("nope") is None

    async def test_expired_returns_none_and_deletes(self, test_settings):
        repo = _make_repo(test_settings)
        req = _make_request(expires_at=utcnow() - timedelta(seconds=1))
        await repo.create(req)
        assert await repo.get_by_request_id(req.request_id) is None
        # Second read still None (file was auto-deleted, no resurrection).
        assert await repo.get_by_request_id(req.request_id) is None


class TestFilePARRepositoryMarkUsed:
    async def test_first_use_true_second_false(self, test_settings):
        repo = _make_repo(test_settings)
        req = _make_request()
        await repo.create(req)
        assert await repo.mark_used(req.request_id) is True
        assert await repo.mark_used(req.request_id) is False
        assert await repo.get_by_request_id(req.request_id) is None

    async def test_missing_false(self, test_settings):
        assert await _make_repo(test_settings).mark_used("nope") is False

    async def test_delete(self, test_settings):
        repo = _make_repo(test_settings)
        req = _make_request()
        await repo.create(req)
        await repo.delete(req.request_id)
        assert await repo.get_by_request_id(req.request_id) is None
