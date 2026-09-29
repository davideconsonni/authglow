"""Execution tests for ``authglow.api.oauth_client`` (COV-BE-011).

``tests/integration/test_oauth_client_api.py`` covers client creation and
the rotate-secret happy path over HTTP. This module drives the handlers
directly to pin the rest of the surface: listing, get/404, update (plus
the ``private_key_jwt`` guard), delete (404/500), the JWT-key challenge
guards, rotate-jwt-key, and activate/deactivate.
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


def _user():
    return SimpleNamespace(id="admin-1", email="admin@example.com")


def _client(**kw):
    from authglow.models.oauth_client import OAuth2Client

    base = {"client_secret": "hashed", "client_name": "Test Client"}
    base.update(kw)
    return OAuth2Client(**base)


def _audit():
    audit = MagicMock()
    audit.log_event = AsyncMock()
    return audit


class TestCreate:
    def test_private_key_jwt_without_jwk_400(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import OAuth2ClientCreate

        data = OAuth2ClientCreate(
            client_name="No Key",
            redirect_uris=["https://example.com/cb"],
            token_endpoint_auth_method="private_key_jwt",
        )
        with pytest.raises(HTTPException) as exc:
            _run(api.create_oauth_client(_request(), data, _user(), MagicMock(), _audit()))
        assert exc.value.status_code == 400


class TestList:
    def test_list_returns_responses(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.list_clients = AsyncMock(
            return_value=[_client(client_name="Alpha"), _client(client_name="Beta")]
        )
        out = _run(api.list_oauth_clients(10, 0, False, _user(), storage))
        assert [c.client_name for c in out] == ["Alpha", "Beta"]
        storage.list_clients.assert_awaited_once_with(limit=10, offset=0, active_only=False)


class TestGet:
    def test_get_found(self):
        from authglow.api import oauth_client as api

        client = _client(client_name="Fetched")
        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=client)
        out = _run(api.get_oauth_client(client.client_id, _user(), storage))
        assert out.client_name == "Fetched"

    def test_get_not_found_404(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.get_oauth_client("missing", _user(), storage))
        assert exc.value.status_code == 404


class TestUpdate:
    def test_update_success_audits(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import OAuth2ClientUpdate

        client = _client(client_name="Old Name")
        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=client)
        storage.update_client = AsyncMock()
        audit = _audit()
        out = _run(
            api.update_oauth_client(
                _request(),
                client.client_id,
                OAuth2ClientUpdate(client_name="New Name"),
                _user(),
                storage,
                audit,
            )
        )
        assert out.client_name == "New Name"
        storage.update_client.assert_awaited_once_with(client)
        assert audit.log_event.await_args.kwargs["metadata"]["updated_fields"] == ["client_name"]

    def test_update_not_found_404(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import OAuth2ClientUpdate

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(
                api.update_oauth_client(
                    _request(),
                    "missing",
                    OAuth2ClientUpdate(client_name="Xyz"),
                    _user(),
                    storage,
                    _audit(),
                )
            )
        assert exc.value.status_code == 404

    def test_update_switch_to_private_key_jwt_without_jwk_400(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import OAuth2ClientUpdate

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=_client())
        with pytest.raises(HTTPException) as exc:
            _run(
                api.update_oauth_client(
                    _request(),
                    "c1",
                    OAuth2ClientUpdate(token_endpoint_auth_method="private_key_jwt"),
                    _user(),
                    storage,
                    _audit(),
                )
            )
        assert exc.value.status_code == 400


class TestDelete:
    def test_delete_success(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=_client(client_name="Bye"))
        storage.delete_client = AsyncMock(return_value=True)
        audit = _audit()
        out = _run(api.delete_oauth_client(_request(), "c1", _user(), storage, audit))
        assert out == {"message": "OAuth2 client deleted successfully"}
        assert audit.log_event.await_args.kwargs["severity"] == "warning"

    def test_delete_not_found_404(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.delete_oauth_client(_request(), "missing", _user(), storage, _audit()))
        assert exc.value.status_code == 404

    def test_delete_failure_500(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=_client())
        storage.delete_client = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            _run(api.delete_oauth_client(_request(), "c1", _user(), storage, _audit()))
        assert exc.value.status_code == 500


class TestRotateSecret:
    def test_client_gone_after_challenge_404(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import RotateSecretConfirm

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        body = RotateSecretConfirm(challenge_id="ch-1", word="correct horse")
        with patch.object(api, "consume_challenge"):
            with pytest.raises(HTTPException) as exc:
                _run(api.rotate_client_secret(_request(), "c1", body, _user(), storage, _audit()))
        assert exc.value.status_code == 404


class TestRotateJwtKeyChallenge:
    def test_not_found_404(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(
                api.request_rotate_jwt_key_challenge(
                    _request(), "missing", _user(), storage, _audit()
                )
            )
        assert exc.value.status_code == 404

    def test_wrong_auth_method_400(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(
            return_value=_client(token_endpoint_auth_method="client_secret_basic")
        )
        with pytest.raises(HTTPException) as exc:
            _run(api.request_rotate_jwt_key_challenge(_request(), "c1", _user(), storage, _audit()))
        assert exc.value.status_code == 400


class TestRotateJwtKey:
    def test_success_returns_new_key(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import RotateSecretConfirm

        client = _client(token_endpoint_auth_method="client_secret_jwt")
        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=client)
        storage.rotate_client_jwt_key = AsyncMock(return_value="NEW-JWT-KEY")
        audit = _audit()
        body = RotateSecretConfirm(challenge_id="ch-1", word="correct horse")
        with patch.object(api, "consume_challenge"):
            out = _run(
                api.rotate_client_jwt_key(
                    _request(), client.client_id, body, _user(), storage, audit
                )
            )
        assert out.new_client_secret == "NEW-JWT-KEY"
        assert out.client_id == client.client_id
        assert audit.log_event.await_args.kwargs["severity"] == "high"

    def test_not_found_404(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import RotateSecretConfirm

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        body = RotateSecretConfirm(challenge_id="ch-1", word="correct horse")
        with patch.object(api, "consume_challenge"):
            with pytest.raises(HTTPException) as exc:
                _run(
                    api.rotate_client_jwt_key(
                        _request(), "missing", body, _user(), storage, _audit()
                    )
                )
        assert exc.value.status_code == 404

    def test_wrong_auth_method_400(self):
        from authglow.api import oauth_client as api
        from authglow.models.oauth_client import RotateSecretConfirm

        storage = MagicMock()
        storage.get_client = AsyncMock(
            return_value=_client(token_endpoint_auth_method="client_secret_basic")
        )
        body = RotateSecretConfirm(challenge_id="ch-1", word="correct horse")
        with patch.object(api, "consume_challenge"):
            with pytest.raises(HTTPException) as exc:
                _run(api.rotate_client_jwt_key(_request(), "c1", body, _user(), storage, _audit()))
        assert exc.value.status_code == 400


class TestActivateDeactivate:
    def test_activate_success(self):
        from authglow.api import oauth_client as api

        client = _client(is_active=False)
        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=client)
        storage.update_client = AsyncMock()
        out = _run(api.activate_oauth_client(client.client_id, _user(), storage, _audit()))
        assert out == {"message": "OAuth2 client activated"}
        assert client.is_active is True

    def test_activate_not_found_404(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.activate_oauth_client("missing", _user(), storage, _audit()))
        assert exc.value.status_code == 404

    def test_deactivate_success(self):
        from authglow.api import oauth_client as api

        client = _client(is_active=True)
        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=client)
        storage.update_client = AsyncMock()
        audit = _audit()
        out = _run(api.deactivate_oauth_client(client.client_id, _user(), storage, audit))
        assert out == {"message": "OAuth2 client deactivated"}
        assert client.is_active is False
        assert audit.log_event.await_args.kwargs["severity"] == "warning"

    def test_deactivate_not_found_404(self):
        from authglow.api import oauth_client as api

        storage = MagicMock()
        storage.get_client = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(api.deactivate_oauth_client("missing", _user(), storage, _audit()))
        assert exc.value.status_code == 404
