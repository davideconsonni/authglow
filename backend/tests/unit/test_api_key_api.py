"""Execution tests for ``authglow.api.api_key`` (COV-BE-012).

``tests/integration/test_api_key_safeword.py`` covers the rotate/delete
safeword handshake over HTTP. This module drives the handlers directly to
pin the rest of the surface: creation (self + admin for another user),
listing, get/update/revoke with ownership and error branches, the
challenge/rotate/delete guards, and the admin listing/cleanup routes.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _user(user_id="u-1"):
    return SimpleNamespace(id=user_id, email=f"{user_id}@example.com", scopes=["read", "write"])


def _key(**kw):
    from authglow.models.api_key import APIKey

    base = {
        "user_id": "u-1",
        "name": "My Key",
        "key_prefix": "ak_ABCDEFGHIJ",
        "key_hash": "hashed",
        "scopes": ["read"],
        "created_by": "u-1",
    }
    base.update(kw)
    return APIKey(**base)


def _audit():
    audit = MagicMock()
    audit.log_event = AsyncMock()
    return audit


def _mocked_storage(*, by_email=..., by_id=...):
    storage = MagicMock()
    storage.get_user_by_email = AsyncMock(return_value=by_email)
    storage.get_user = AsyncMock(return_value=by_id)
    return storage


class TestCreate:
    def test_self_service_success_reports_scope_filter(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyCreate

        key = _key(scopes=["read"])
        service = MagicMock()
        service.create_key = AsyncMock(return_value=(key, "ak_plaintext"))
        audit = _audit()
        data = APIKeyCreate(name="My Key", scopes=["read", "write"])
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            out = _run(api.create_api_key(_request(), data, _user(), service, audit))
        assert out.api_key == "ak_plaintext"
        assert out.granted_scopes == ["read"]
        assert out.filtered_scopes == ["write"]
        service.create_key.assert_awaited_once()
        assert service.create_key.await_args.kwargs["user_id"] == "u-1"
        audit.log_event.assert_awaited_once()

    def test_other_user_without_permission_403(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyCreate

        data = APIKeyCreate(name="For Other", user_email="other@example.com")
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.create_api_key(_request(), data, _user(), MagicMock(), _audit()))
        assert exc.value.status_code == 403

    def test_other_user_not_found_404(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyCreate

        data = APIKeyCreate(name="For Other", user_email="ghost@example.com")
        with (
            patch.object(api, "user_has_permission", AsyncMock(return_value=True)),
            patch.object(api, "UserStorage", return_value=_mocked_storage(by_email=None)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.create_api_key(_request(), data, _user(), MagicMock(), _audit()))
        assert exc.value.status_code == 404

    def test_other_user_success_uses_target_owner(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyCreate

        target = SimpleNamespace(id="u-target", email="other@example.com")
        key = _key(user_id="u-target")
        service = MagicMock()
        service.create_key = AsyncMock(return_value=(key, "ak_plaintext"))
        data = APIKeyCreate(name="For Other", user_email="other@example.com")
        with (
            patch.object(api, "user_has_permission", AsyncMock(return_value=True)),
            patch.object(api, "UserStorage", return_value=_mocked_storage(by_email=target)),
        ):
            out = _run(api.create_api_key(_request(), data, _user(), service, _audit()))
        assert out.user_id == "u-target"
        assert service.create_key.await_args.kwargs["user_id"] == "u-target"


class TestListAndGet:
    def test_list_my_keys(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_user_keys = AsyncMock(return_value=[_key(name="A"), _key(name="B")])
        out = _run(api.list_my_api_keys(_user(), service))
        assert [k.name for k in out] == ["A", "B"]

    def test_get_own_key_enriches_email(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-1"))
        owner = SimpleNamespace(email="u-1@example.com")
        with patch.object(api, "UserStorage", return_value=_mocked_storage(by_id=owner)):
            out = _run(api.get_api_key("k1", _user(), service))
        assert out.user_email == "u-1@example.com"

    def test_get_missing_404(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.get_api_key("missing", _user(), service))
        assert exc.value.status_code == 404

    def test_get_foreign_key_without_permission_403(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.get_api_key("k1", _user(), service))
        assert exc.value.status_code == 403

    def test_get_foreign_key_as_admin_allowed(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        with (
            patch.object(api, "user_has_permission", AsyncMock(return_value=True)),
            patch.object(api, "UserStorage", return_value=_mocked_storage(by_id=None)),
        ):
            out = _run(api.get_api_key("k1", _user(), service))
        assert out.user_email is None


class TestUpdate:
    def test_update_success(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyUpdate

        key = _key()
        updated = _key(name="Renamed")
        service = MagicMock()
        service.get_key = AsyncMock(return_value=key)
        service.update_key = AsyncMock(return_value=updated)
        audit = _audit()
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            out = _run(
                api.update_api_key(
                    _request(), "k1", APIKeyUpdate(name="Renamed"), _user(), service, audit
                )
            )
        assert out.name == "Renamed"
        assert audit.log_event.await_args.kwargs["metadata"]["updates"] == ["name"]

    def test_update_missing_404(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyUpdate

        service = MagicMock()
        service.get_key = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(
                api.update_api_key(
                    _request(), "missing", APIKeyUpdate(name="Xyz"), _user(), service, _audit()
                )
            )
        assert exc.value.status_code == 404

    def test_update_foreign_without_permission_403(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyUpdate

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(
                    api.update_api_key(
                        _request(), "k1", APIKeyUpdate(name="Xyz"), _user(), service, _audit()
                    )
                )
        assert exc.value.status_code == 403

    def test_update_returns_none_404(self):
        from authglow.api import api_key as api
        from authglow.models.api_key import APIKeyUpdate

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key())
        service.update_key = AsyncMock(return_value=None)
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(
                    api.update_api_key(
                        _request(), "k1", APIKeyUpdate(name="Xyz"), _user(), service, _audit()
                    )
                )
        assert exc.value.status_code == 404


class TestRevoke:
    def test_revoke_success(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key())
        service.revoke_key = AsyncMock(return_value=True)
        audit = _audit()
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            out = _run(api.revoke_api_key(_request(), "k1", _user(), service, audit))
        assert out == {"message": "API key revoked successfully"}
        assert audit.log_event.await_args.kwargs["severity"] == "warning"

    def test_revoke_missing_404(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.revoke_api_key(_request(), "missing", _user(), service, _audit()))
        assert exc.value.status_code == 404

    def test_revoke_foreign_without_permission_403(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.revoke_api_key(_request(), "k1", _user(), service, _audit()))
        assert exc.value.status_code == 403

    def test_revoke_failure_500(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key())
        service.revoke_key = AsyncMock(return_value=False)
        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.revoke_api_key(_request(), "k1", _user(), service, _audit()))
        assert exc.value.status_code == 500


class TestDeleteFlow:
    def test_delete_foreign_without_permission_403(self):
        from authglow.api import api_key as api
        from authglow.api.api_key import SafewordConfirm

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        body = SafewordConfirm(challenge_id="ch", word="w")
        with (
            patch.object(api, "consume_challenge"),
            patch.object(api, "user_has_permission", AsyncMock(return_value=False)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.delete_api_key(_request(), "k1", body, _user(), service, _audit()))
        assert exc.value.status_code == 403

    def test_delete_failure_500(self):
        from authglow.api import api_key as api
        from authglow.api.api_key import SafewordConfirm

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key())
        service.delete_key = AsyncMock(return_value=False)
        body = SafewordConfirm(challenge_id="ch", word="w")
        with (
            patch.object(api, "consume_challenge"),
            patch.object(api, "user_has_permission", AsyncMock(return_value=False)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.delete_api_key(_request(), "k1", body, _user(), service, _audit()))
        assert exc.value.status_code == 500


class TestRotateFlow:
    def test_rotate_challenge_missing_404(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.request_rotate_api_key_challenge(_request(), "missing", _user(), service))
        assert exc.value.status_code == 404

    def test_rotate_foreign_without_permission_403(self):
        from authglow.api import api_key as api
        from authglow.api.api_key import SafewordConfirm

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-other"))
        body = SafewordConfirm(challenge_id="ch", word="w")
        with (
            patch.object(api, "consume_challenge"),
            patch.object(api, "user_has_permission", AsyncMock(return_value=False)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.rotate_api_key(_request(), "k1", body, _user(), service, _audit()))
        assert exc.value.status_code == 403

    def test_rotate_failure_500(self):
        from authglow.api import api_key as api
        from authglow.api.api_key import SafewordConfirm

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key())
        service.rotate_key = AsyncMock(return_value=None)
        body = SafewordConfirm(challenge_id="ch", word="w")
        with (
            patch.object(api, "consume_challenge"),
            patch.object(api, "user_has_permission", AsyncMock(return_value=False)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.rotate_api_key(_request(), "k1", body, _user(), service, _audit()))
        assert exc.value.status_code == 500


class TestAdminEndpoints:
    def test_list_all_requires_permission_403(self):
        from authglow.api import api_key as api

        with patch.object(api, "user_has_any_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.list_all_api_keys(100, 0, False, _user(), MagicMock()))
        assert exc.value.status_code == 403

    def test_list_all_enriches_email(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.list_all_keys = AsyncMock(return_value=[_key(user_id="u-9")])
        owner = SimpleNamespace(email="u-9@example.com")
        with (
            patch.object(api, "user_has_any_permission", AsyncMock(return_value=True)),
            patch.object(api, "UserStorage", return_value=_mocked_storage(by_id=owner)),
        ):
            out = _run(api.list_all_api_keys(100, 0, False, _user(), service))
        assert out[0].user_email == "u-9@example.com"

    def test_get_single_requires_permission_403(self):
        from authglow.api import api_key as api

        with patch.object(api, "user_has_any_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.get_single_api_key("k1", _user(), MagicMock()))
        assert exc.value.status_code == 403

    def test_get_single_missing_404(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=None)
        with patch.object(api, "user_has_any_permission", AsyncMock(return_value=True)):
            with pytest.raises(HTTPException) as exc:
                _run(api.get_single_api_key("missing", _user(), service))
        assert exc.value.status_code == 404

    def test_get_single_success(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_key = AsyncMock(return_value=_key(user_id="u-9"))
        with (
            patch.object(api, "user_has_any_permission", AsyncMock(return_value=True)),
            patch.object(api, "UserStorage", return_value=_mocked_storage(by_id=None)),
        ):
            out = _run(api.get_single_api_key("k1", _user(), service))
        assert out.user_email is None

    def test_list_user_keys_requires_permission_403(self):
        from authglow.api import api_key as api

        with patch.object(api, "user_has_any_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.list_user_api_keys("u-9", _user(), MagicMock()))
        assert exc.value.status_code == 403

    def test_list_user_keys_success(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.get_user_keys = AsyncMock(return_value=[_key(user_id="u-9")])
        with patch.object(api, "user_has_any_permission", AsyncMock(return_value=True)):
            out = _run(api.list_user_api_keys("u-9", _user(), service))
        assert len(out) == 1

    def test_cleanup_requires_permission_403(self):
        from authglow.api import api_key as api

        with patch.object(api, "user_has_permission", AsyncMock(return_value=False)):
            with pytest.raises(HTTPException) as exc:
                _run(api.cleanup_expired_keys(_user(), MagicMock(), _audit()))
        assert exc.value.status_code == 403

    def test_cleanup_success_audits(self):
        from authglow.api import api_key as api

        service = MagicMock()
        service.cleanup_expired_keys = AsyncMock(return_value=5)
        audit = _audit()
        with patch.object(api, "user_has_permission", AsyncMock(return_value=True)):
            out = _run(api.cleanup_expired_keys(_user(), service, audit))
        assert out == {"message": "Cleaned up 5 expired API keys"}
        audit.log_event.assert_awaited_once()
