"""Execution tests for ``authglow.api.par`` (COV-BE-014).

The RFC 9126 happy path and the authorize-side integration live in
``tests/conformance/test_par.py``. This module drives the handler
directly to pin the error surface it never reaches: missing/invalid
client, bad or absent ``redirect_uri``, non-``code`` response type, the
two PKCE guards, scope validation failure, and the best-effort audit
that must never break a successful response.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import Request

from authglow.api.oauth_errors import OAuth2Error


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _call(
    *,
    redirect_uri="https://example.com/cb",
    client_id="c1",
    response_type=None,
    scope="read",
    code_challenge="challenge-value",
    oauth_client=...,
    verify_redirect=True,
    process_raises=False,
    audit_raises=False,
    enforce_pkce=True,
):
    from authglow.api import par as par_api

    settings = SimpleNamespace(
        enforce_pkce=enforce_pkce, par_request_uri_ttl_seconds=90, issuer="https://iss"
    )
    oauth2 = MagicMock()
    oauth2.verify_redirect_uri = AsyncMock(return_value=verify_redirect)
    if process_raises:
        oauth2.process_scopes = AsyncMock(side_effect=ValueError("unknown scope"))
    else:
        oauth2.process_scopes = AsyncMock(return_value=scope.split() if scope else [])

    par_svc = MagicMock()
    par = SimpleNamespace(request_id="req-1", request_uri="urn:ietf:params:oauth:request_uri:abc")
    par_svc.create_request = AsyncMock(return_value=par)

    audit = MagicMock()
    if audit_raises:
        audit.log_event = AsyncMock(side_effect=RuntimeError("sink down"))
    else:
        audit.log_event = AsyncMock()

    resolved_client = (
        SimpleNamespace(client_id="c1", require_pkce=False) if oauth_client is ... else oauth_client
    )

    with (
        patch.object(par_api, "get_settings", return_value=settings),
        patch.object(
            par_api,
            "_authenticate_client_at_token_endpoint",
            AsyncMock(return_value=resolved_client),
        ),
        patch.object(par_api, "_enforce_grant_allowed", AsyncMock()),
    ):
        out = _run(
            par_api.pushed_authorization_request(
                _request(),
                redirect_uri,
                client_id=client_id,
                client_secret=None,
                response_type=response_type,
                scope=scope,
                state=None,
                code_challenge=code_challenge,
                code_challenge_method="S256" if code_challenge else None,
                nonce=None,
                prompt=None,
                max_age=None,
                claims=None,
                client_assertion_type=None,
                client_assertion=None,
                oauth2_service=oauth2,
                par_service=par_svc,
                audit_service=audit,
            )
        )
    return out, par_svc, audit


class TestServiceFactories:
    def test_get_oauth2_service(self):
        from authglow.api import par as par_api

        with patch.object(par_api, "OAuth2Service") as cls:
            assert par_api.get_oauth2_service() is cls.return_value

    def test_get_par_service(self):
        from authglow.api import par as par_api

        with patch.object(par_api, "PushedAuthorizationService") as cls:
            assert par_api.get_par_service() is cls.return_value

    def test_get_audit_service(self):
        from authglow.api import par as par_api

        with patch.object(par_api, "AuditService") as cls:
            assert par_api.get_audit_service() is cls.return_value


class TestClientValidation:
    def test_missing_client_id_400(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(client_id=None)
        assert exc.value.status_code == 400

    def test_invalid_client_credentials_401(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(oauth_client=None)
        assert exc.value.status_code == 401


class TestRedirectUri:
    def test_empty_redirect_uri_400(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(redirect_uri="")
        assert exc.value.status_code == 400

    def test_unregistered_redirect_uri_400(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(verify_redirect=False)
        assert exc.value.status_code == 400


class TestResponseType:
    def test_non_code_response_type_400(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(response_type="token")
        assert exc.value.status_code == 400

    def test_code_response_type_accepted(self):
        out, _, _ = _call(response_type="code")
        assert out.request_uri == "urn:ietf:params:oauth:request_uri:abc"


class TestPkceGuards:
    def test_global_enforce_pkce_requires_challenge(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(code_challenge=None, enforce_pkce=True)
        assert exc.value.status_code == 400

    def test_client_require_pkce_requires_challenge(self):
        oauth_client = SimpleNamespace(client_id="c1", require_pkce=True)
        with pytest.raises(OAuth2Error) as exc:
            _call(code_challenge=None, enforce_pkce=False, oauth_client=oauth_client)
        assert exc.value.status_code == 400


class TestScopeAndAudit:
    def test_invalid_scope_400(self):
        with pytest.raises(OAuth2Error) as exc:
            _call(process_raises=True)
        assert exc.value.status_code == 400

    def test_success_returns_request_uri(self):
        out, par_svc, audit = _call(scope="read write")
        assert out.request_uri == "urn:ietf:params:oauth:request_uri:abc"
        assert out.expires_in == 90
        par_svc.create_request.assert_awaited_once()
        assert par_svc.create_request.await_args.kwargs["scope"] == "read write"
        audit.log_event.assert_awaited_once()

    def test_audit_failure_does_not_break_response(self):
        out, _, audit = _call(audit_raises=True)
        assert out.request_uri == "urn:ietf:params:oauth:request_uri:abc"
        audit.log_event.assert_awaited_once()
