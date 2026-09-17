"""Strict ``token_endpoint_auth_method`` enforcement at the token endpoint.

Direct tests for ``_authenticate_client_at_token_endpoint`` (auth.py):
exactly one method per request, and the method must match the
registration. Service-level matrix lives in
``tests/unit/test_oauth2.py::TestVerifyClientStrictMethod``.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from authglow.api.oauth_errors import OAuth2Error


def _client(method, *, confidential=True):
    from authglow.models.oauth_client import OAuth2Client

    return OAuth2Client(
        client_id="cid-strict-helper",
        client_secret="hashed-placeholder",
        client_name="Strict Helper Client",
        redirect_uris=["https://app.example.com/callback"],
        token_endpoint_auth_method=method,
        is_confidential=confidential,
    )


def _service(client):
    svc = MagicMock()
    svc.client_storage.get_client = AsyncMock(return_value=client)
    svc.client_storage.update_last_used = AsyncMock()
    svc.verify_client = AsyncMock(return_value=True)
    return svc


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestAuthenticateClientStrictMethod:
    def _auth(self, svc, **kwargs):
        from authglow.api import auth as auth_mod

        with patch.object(auth_mod, "get_settings") as mock_settings:
            from authglow.core.config import get_settings as _real

            mock_settings.return_value = _real()
            return _run(
                auth_mod._authenticate_client_at_token_endpoint(
                    MagicMock(), svc, **kwargs
                )
            )

    def test_basic_via_basic_header_ok(self, test_settings):
        svc = _service(_client("client_secret_basic"))
        out = self._auth(
            svc,
            resolved_client_id="cid-strict-helper",
            resolved_client_secret="s3cret",
            basic_client_secret="s3cret",
            form_client_secret=None,
        )
        assert out.client_id == "cid-strict-helper"
        svc.verify_client.assert_awaited_once_with(
            "cid-strict-helper", "s3cret", auth_method="client_secret_basic"
        )

    def test_basic_via_post_rejected(self, test_settings):
        svc = _service(_client("client_secret_basic"))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret="s3cret",
                basic_client_secret=None,
                form_client_secret="s3cret",
            )
        assert exc.value.status_code == 401
        assert exc.value.error == "invalid_client"
        svc.verify_client.assert_not_awaited()

    def test_jwt_client_with_secret_rejected(self, test_settings):
        svc = _service(_client("private_key_jwt"))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret="s3cret",
                basic_client_secret="s3cret",
                form_client_secret=None,
            )
        assert exc.value.status_code == 401
        assert "client_assertion required" in exc.value.body["error_description"]
        svc.verify_client.assert_not_awaited()

    def test_basic_client_with_assertion_rejected(self, test_settings):
        svc = _service(_client("client_secret_basic"))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret=None,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion="junk.assertion",
            )
        assert exc.value.status_code == 401
        assert "not allowed" in exc.value.body["error_description"]

    def test_secret_plus_assertion_rejected(self, test_settings):
        svc = _service(_client("private_key_jwt"))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret="s3cret",
                basic_client_secret="s3cret",
                form_client_secret=None,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion="junk.assertion",
            )
        assert exc.value.status_code == 400
        assert exc.value.error == "invalid_request"

    def test_basic_plus_post_rejected(self, test_settings):
        svc = _service(_client("client_secret_basic"))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret="s3cret",
                basic_client_secret="s3cret",
                form_client_secret="s3cret",
            )
        assert exc.value.status_code == 400
        assert exc.value.error == "invalid_request"

    def test_public_client_with_secret_rejected(self, test_settings):
        svc = _service(_client("none", confidential=False))
        with pytest.raises(OAuth2Error) as exc:
            self._auth(
                svc,
                resolved_client_id="cid-strict-helper",
                resolved_client_secret="s3cret",
                basic_client_secret=None,
                form_client_secret="s3cret",
            )
        assert exc.value.status_code == 401
        assert exc.value.error == "invalid_client"

    def test_public_client_without_secret_ok(self, test_settings):
        svc = _service(_client("none", confidential=False))
        out = self._auth(
            svc,
            resolved_client_id="cid-strict-helper",
            resolved_client_secret=None,
            basic_client_secret=None,
            form_client_secret=None,
        )
        assert out.client_id == "cid-strict-helper"
