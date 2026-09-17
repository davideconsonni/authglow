"""Execution tests for ``authglow.api.federation`` (COV-BE-005).

Covers the public login/callback endpoints, the consent-session check
and the admin provider CRUD. All services are mocked at the API-module
boundary; handlers are invoked directly with a real starlette
``Request`` (the limiter rejects mocks).
"""

import asyncio
from datetime import timedelta
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


def _provider(**kw):
    from authglow.models.federation import ExternalIdpConfig

    base = {
        "id": "google",
        "label": "Google",
        "issuer": "https://accounts.google.com",
        "client_id": "cid",
        "client_secret": "sekret",
        "enabled": True,
    }
    base.update(kw)
    return ExternalIdpConfig(**base)


def _user(**kw):
    from authglow.models.user import User

    base = {"id": "u-1", "email": "u@example.com", "hashed_password": "x", "scopes": ["read"]}
    base.update(kw)
    return User(**base)


def _oauth_client(**kw):
    base = {"client_id": "web-client", "is_active": True, "client_name": "Web"}
    base.update(kw)
    return SimpleNamespace(**base)


class TestFactories:
    def test_factories(self):
        from authglow.api import federation as fed_api
        from authglow.services.audit import AuditService
        from authglow.services.federation_provider import FederationProviderService
        from authglow.services.user import UserService

        assert isinstance(fed_api.get_audit_service(), AuditService)
        assert isinstance(fed_api.get_federation_storage(), FederationProviderService)
        assert isinstance(fed_api.get_user_storage(), UserService)


class TestListProviders:
    def test_returns_providers(self):
        from authglow.api import federation as fed_api

        svc = MagicMock()
        svc.get_providers_for_ui = AsyncMock(return_value=[{"id": "google"}])
        with patch.object(fed_api, "FederationService", return_value=svc):
            out = _run(fed_api.list_public_providers(_request(), None, MagicMock()))
        assert out == [{"id": "google"}]
        svc.get_providers_for_ui.assert_awaited_once_with(context=None)

    def test_context_filter(self):
        from authglow.api import federation as fed_api

        svc = MagicMock()
        svc.get_providers_for_ui = AsyncMock(return_value=[])
        with patch.object(fed_api, "FederationService", return_value=svc):
            _run(fed_api.list_public_providers(_request(), "oauth2", MagicMock()))
        svc.get_providers_for_ui.assert_awaited_once_with(context="oauth2")


class TestFederationLogin:
    def _call(self, provider, **query):
        from authglow.api import federation as fed_api

        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=provider)
        svc = MagicMock()
        svc.get_authorization_url = AsyncMock(return_value=("https://idp/auth?x=1", "s", "n"))
        audit = MagicMock()
        audit.log_event = AsyncMock()
        state_cls = MagicMock()
        state_cls().sign.return_value = {"state": "s", "nonce": "n"}
        # Direct handler calls do not resolve Query() defaults —
        # pass every optional explicitly.
        params = {
            "redirect_uri": "/auth/callback",
            "acr_values": None,
            "client_id": None,
            "oauth_redirect_uri": None,
            "scope": None,
            "app_state": None,
            "code_challenge": None,
            "code_challenge_method": None,
            "response_type": None,
            "oidc_nonce": None,
        }
        params.update(query)
        with (
            patch.object(fed_api, "FederationService", return_value=svc),
            patch.object(fed_api, "AuditService", return_value=audit),
            patch.object(fed_api, "FederationStateToken", state_cls),
            patch.object(
                fed_api,
                "get_settings",
                return_value=SimpleNamespace(base_url="https://app.example.com"),
            ),
        ):
            return _run(
                fed_api.federation_login(_request(), "google", storage=storage, **params)
            ), audit

    def test_unknown_provider_404(self):
        from authglow.api import federation as fed_api

        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(fed_api.federation_login(_request(), "nope", storage=storage))
        assert exc.value.status_code == 404

    def test_disabled_provider_404(self):
        from authglow.api import federation as fed_api

        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=_provider(enabled=False))
        with pytest.raises(HTTPException) as exc:
            _run(fed_api.federation_login(_request(), "google", storage=storage))
        assert exc.value.status_code == 404

    def test_bad_issuer_400(self):
        from authglow.api import federation as fed_api

        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=_provider(issuer="ftp://evil"))
        with pytest.raises(HTTPException) as exc:
            _run(fed_api.federation_login(_request(), "google", storage=storage))
        assert exc.value.status_code == 400

    def test_success_redirects(self):
        resp, audit = self._call(_provider())
        assert resp.status_code == 302
        assert resp.headers["location"] == "https://idp/auth?x=1"
        assert audit.log_event.await_args.kwargs["event_type"] == "federated_login_initiated"

    def test_success_with_oauth2_context(self):
        resp, audit = self._call(
            _provider(),
            redirect_uri="/auth/callback",
            client_id="web-client",
            oauth_redirect_uri="https://app/cb",
            scope="openid read",
        )
        assert resp.status_code == 302
        assert audit.log_event.await_args.kwargs["client_id"] == "web-client"

    def test_provider_unreachable_502(self):
        from authglow.api import federation as fed_api

        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=_provider())
        state_cls = MagicMock()
        state_cls().sign.return_value = {"state": "s", "nonce": "n"}
        svc = MagicMock()
        svc.get_authorization_url = AsyncMock(side_effect=RuntimeError("dns"))
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with (
            patch.object(fed_api, "FederationService", return_value=svc),
            patch.object(fed_api, "AuditService", return_value=audit),
            patch.object(fed_api, "FederationStateToken", state_cls),
            patch.object(
                fed_api,
                "get_settings",
                return_value=SimpleNamespace(base_url="https://app.example.com"),
            ),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    fed_api.federation_login(
                        _request(),
                        "google",
                        redirect_uri="/auth/callback",
                        acr_values=None,
                        client_id=None,
                        oauth_redirect_uri=None,
                        scope=None,
                        app_state=None,
                        code_challenge=None,
                        code_challenge_method=None,
                        response_type=None,
                        oidc_nonce=None,
                        storage=storage,
                    )
                )
        assert exc.value.status_code == 502


def _callback_mocks(*, claims=None, provider=None, existing=None, by_email=None):
    """Shared mocks for ``federation_callback`` with sane success defaults."""
    from authglow.api import federation as fed_api

    state_claims = {
        "provider_id": "google",
        "redirect_uri": "https://app.example.com/api/federation/callback",
        "nonce": "n-1",
    }
    if claims:
        state_claims.update(claims)
    state_cls = MagicMock()
    state_cls().verify.return_value = state_claims
    state_cls.get_oauth2_context.return_value = state_claims.get("oauth2_context")

    storage = MagicMock()
    storage.get_provider = AsyncMock(return_value=provider if provider is not None else _provider())

    fed_svc = MagicMock()
    fed_svc.exchange_code = AsyncMock(return_value={"access_token": "idp-at"})
    fed_svc.verify_id_token = AsyncMock()
    fed_svc.fetch_userinfo = AsyncMock(return_value={"sub": "ext-1"})
    fed_svc.map_claims_to_user = AsyncMock(
        return_value={"external_id": "ext-1", "email": "ext@example.com"}
    )

    user_storage = MagicMock()
    user_storage.get_by_external_id = AsyncMock(return_value=existing)
    user_storage.get_user_by_email = AsyncMock(return_value=by_email)
    created = _user()
    user_storage.create_user = AsyncMock(side_effect=lambda u: u)
    user_storage.link_federated_identity = AsyncMock()
    user_storage.update_user = AsyncMock()
    user_storage.update_last_login = AsyncMock()

    audit = MagicMock()
    audit.log_event = AsyncMock()
    login_svc = MagicMock()
    login_svc.record_login = AsyncMock()
    rt_svc = MagicMock()
    rt_svc.create_refresh_token = AsyncMock(
        return_value=SimpleNamespace(token="rt-1", token_id="rtid-1")
    )
    jwt_svc = MagicMock()
    jwt_svc.create_token_response = MagicMock(
        return_value=SimpleNamespace(access_token="at-1", refresh_token="rt-2")
    )
    claim_svc = MagicMock()
    claim_svc.build_claims = AsyncMock(return_value={})

    patches = [
        patch.object(fed_api, "FederationStateToken", state_cls),
        patch.object(fed_api, "FederationService", return_value=fed_svc),
        patch.object(fed_api, "AuditService", return_value=audit),
        patch.object(fed_api, "LoginHistoryService", return_value=login_svc),
        # RefreshTokenService / ClaimPolicyService are imported lazily
        # inside the handler — patch at the source modules.
        patch("authglow.services.refresh_token.RefreshTokenService", return_value=rt_svc),
        patch("authglow.services.claim_policy.ClaimPolicyService", return_value=claim_svc),
        patch.object(fed_api, "get_jwt_service", return_value=jwt_svc),
        patch.object(
            fed_api,
            "get_settings",
            return_value=SimpleNamespace(
                refresh_token_expire_days=30,
                access_token_expire_minutes=30,
                auth_cookie_access_name="at",
                auth_cookie_refresh_name="rt",
                auth_cookie_secure=False,
                auth_cookie_path="/",
                frontend_base_url="https://app.example.com",
            ),
        ),
        patch("authglow.services.password.hash_password_async", return_value="hashed"),
    ]
    mocks = {
        "state_cls": state_cls,
        "storage": storage,
        "fed_svc": fed_svc,
        "user_storage": user_storage,
        "audit": audit,
        "jwt_svc": jwt_svc,
        "claims": state_claims,
    }
    return patches, mocks


def _run_callback(patches, mocks, **kwargs):
    from authglow.api import federation as fed_api
    from contextlib import ExitStack

    # provider_id's Query()/Depends() defaults are not resolved on
    # direct calls — pass every dependency explicitly.
    params = {
        "request": _request(),
        "code": "authcode",
        "state": "state-jwt",
        "provider_id": None,
        "storage": mocks["storage"],
        "audit_service": mocks["audit"],
        "user_storage": mocks["user_storage"],
    }
    params.update(kwargs)
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        return _run(fed_api.federation_callback(**params)), mocks


class TestFederationCallbackGuards:
    def test_invalid_state_400(self):
        from authglow.api import federation as fed_api
        from authglow.services.federation_state import FederationStateError

        state_cls = MagicMock()
        state_cls().verify.side_effect = FederationStateError("tampered")
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with (
            patch.object(fed_api, "FederationStateToken", state_cls),
            patch.object(fed_api, "AuditService", return_value=audit),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    fed_api.federation_callback(
                        _request(),
                        "code",
                        "bad-state",
                        provider_id="google",
                        storage=MagicMock(),
                        audit_service=audit,
                        user_storage=MagicMock(),
                    )
                )
        assert exc.value.status_code == 400

    def test_missing_provider_400(self):
        patches, mocks = _callback_mocks(claims={"provider_id": None})
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks, provider_id=None)
        assert exc.value.status_code == 400

    def test_provider_mismatch_400(self):
        patches, mocks = _callback_mocks()
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks, provider_id="github")
        assert exc.value.status_code == 400
        assert mocks["audit"].log_event.await_count == 1

    def test_unknown_provider_404(self):
        patches, mocks = _callback_mocks(provider=None)
        mocks["storage"].get_provider = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 404


class TestFederationCallbackLogin:
    def test_new_user_dashboard_redirect(self):
        patches, mocks = _callback_mocks()
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith("https://app.example.com/dashboard")
        assert resp.headers["location"].endswith("?fed=1")
        mocks["user_storage"].create_user.assert_awaited_once()
        events = [c.kwargs["event_type"] for c in mocks["audit"].log_event.await_args_list]
        assert "federated_login_success" in events

    def test_existing_user_names_updated(self):
        patches, mocks = _callback_mocks(existing=_user())
        mocks["fed_svc"].map_claims_to_user = AsyncMock(
            return_value={
                "external_id": "ext-1",
                "email": "ext@example.com",
                "given_name": "New",
                "family_name": "Name",
            }
        )
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        mocks["user_storage"].update_user.assert_awaited_once()

    def test_existing_inactive_user_403(self):
        patches, mocks = _callback_mocks(existing=_user(is_active=False))
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 403

    def test_suspended_user_423(self):
        from authglow.core.datetime import utcnow

        patches, mocks = _callback_mocks(
            existing=_user(suspended_until=utcnow() + timedelta(hours=1))
        )
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 423

    def test_email_link_verified(self):
        patches, mocks = _callback_mocks(by_email=_user())
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": True}
        )
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        mocks["user_storage"].link_federated_identity.assert_awaited_once()

    def test_email_link_unverified_403(self):
        patches, mocks = _callback_mocks(by_email=_user())
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": False}
        )
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 403

    def test_no_access_token_400(self):
        patches, mocks = _callback_mocks()
        mocks["fed_svc"].exchange_code = AsyncMock(return_value={})
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400

    def test_bad_id_token_400(self):
        patches, mocks = _callback_mocks()
        mocks["fed_svc"].exchange_code = AsyncMock(
            return_value={"access_token": "idp-at", "id_token": "bad.jwt"}
        )
        mocks["fed_svc"].verify_id_token = AsyncMock(side_effect=RuntimeError("sig"))
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400

    def test_generic_failure_400(self):
        patches, mocks = _callback_mocks()
        mocks["fed_svc"].fetch_userinfo = AsyncMock(side_effect=RuntimeError("down"))
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400
        assert exc.value.detail == "Federation login failed"

    def test_new_user_without_email_400(self):
        # Mapped claims without email take the federated.local fallback,
        # which the email validator rejects — the flow fails closed
        # with the generic 400 (behavior pinned, not changed here).
        patches, mocks = _callback_mocks()
        mocks["fed_svc"].map_claims_to_user = AsyncMock(
            return_value={"external_id": "ext-1"}
        )
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400
        mocks["user_storage"].create_user.assert_not_awaited()

    def test_email_link_id_token_fallback_verified(self):
        import jwt as pyjwt

        patches, mocks = _callback_mocks(by_email=_user())
        id_token = pyjwt.encode({"email_verified": True}, "whatever", algorithm="HS256")
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": False}
        )
        mocks["fed_svc"].exchange_code = AsyncMock(
            return_value={"access_token": "idp-at", "id_token": id_token}
        )
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        mocks["user_storage"].link_federated_identity.assert_awaited_once()

    def test_email_link_id_token_undecodable_403(self):
        patches, mocks = _callback_mocks(by_email=_user())
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": False}
        )
        mocks["fed_svc"].exchange_code = AsyncMock(
            return_value={"access_token": "idp-at", "id_token": "not-a-jwt"}
        )
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 403

    def test_email_link_inactive_403(self):
        patches, mocks = _callback_mocks(by_email=_user(is_active=False))
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": True}
        )
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 403

    def test_email_link_names_updated(self):
        patches, mocks = _callback_mocks(by_email=_user())
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": True}
        )
        mocks["fed_svc"].map_claims_to_user = AsyncMock(
            return_value={
                "external_id": "ext-9",
                "email": "u@example.com",
                "given_name": "New",
                "family_name": "Name",
            }
        )
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        updated = mocks["user_storage"].update_user.await_args.args[0]
        assert updated.first_name == "New"
        assert updated.last_name == "Name"

    def test_email_link_no_update_needed(self):
        patches, mocks = _callback_mocks(
            by_email=_user(is_federated=True, email_verified=True)
        )
        mocks["fed_svc"].fetch_userinfo = AsyncMock(
            return_value={"sub": "ext-9", "email_verified": True}
        )
        mocks["fed_svc"].map_claims_to_user = AsyncMock(
            return_value={"external_id": "ext-9", "email": "u@example.com"}
        )
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        mocks["user_storage"].update_user.assert_not_awaited()
        mocks["user_storage"].link_federated_identity.assert_awaited_once()


class TestFederationCallbackOAuth2Bridge:
    def _oauth_mocks(self, *, consent=True, client="default"):
        ctx = {
            "client_id": "web-client",
            "oauth_redirect_uri": "https://app/cb",
            "scope": "openid read",
            "app_state": "st-1",
            "code_challenge": "ch",
            "code_challenge_method": "S256",
            "oidc_nonce": "n-1",
        }
        patches, mocks = _callback_mocks(claims={"oauth2_context": ctx})
        mocks["state_cls"].get_oauth2_context.return_value = ctx

        from authglow.api import federation as fed_api

        oauth2_svc = MagicMock()
        oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
        oauth2_svc.process_scopes = AsyncMock(return_value=["openid", "read"])
        oauth2_svc.create_authorization_code = AsyncMock(
            return_value=SimpleNamespace(code="authcode-1")
        )
        consent_svc = MagicMock()
        consent_svc.check_consent = AsyncMock(return_value=(consent, None))
        session_svc = MagicMock()
        session_svc.create_consent_session = AsyncMock(
            return_value={"session_token": "consent-1"}
        )
        resolved = _oauth_client() if client == "default" else client
        patches += [
            # OAuth2Service / storages are imported lazily inside the
            # handler — patch at the source modules. SessionService is
            # a module attribute of api.federation.
            patch("authglow.services.oauth2.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.services.oauth_client.OAuth2ClientStorage",
                return_value=_oauth_storage(resolved),
            ),
            patch(
                "authglow.services.oauth_consent.OAuth2ConsentService",
                return_value=consent_svc,
            ),
            patch.object(fed_api, "SessionService", return_value=session_svc),
        ]
        mocks["oauth2_svc"] = oauth2_svc
        return patches, mocks

    def test_consent_redirects_with_code(self):
        patches, mocks = self._oauth_mocks(consent=True)
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        assert "code=authcode-1" in resp.headers["location"]
        assert "state=st-1" in resp.headers["location"]

    def test_no_consent_redirects_to_authorize(self):
        patches, mocks = self._oauth_mocks(consent=False)
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        assert "/oauth2/authorize?fed=1" in resp.headers["location"]
        assert resp.headers["location"].startswith("https://app.example.com")

    def test_unknown_oauth_client_400(self):
        patches, mocks = self._oauth_mocks(consent=True, client=None)
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400

    def test_invalid_redirect_uri_400(self):
        patches, mocks = self._oauth_mocks(consent=True)
        mocks["oauth2_svc"].verify_redirect_uri = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400

    def test_invalid_scope_400(self):
        patches, mocks = self._oauth_mocks(consent=True)
        mocks["oauth2_svc"].process_scopes = AsyncMock(side_effect=ValueError("nope"))
        with pytest.raises(HTTPException) as exc:
            _run_callback(patches, mocks)
        assert exc.value.status_code == 400

    def test_consent_without_app_state(self):
        patches, mocks = self._oauth_mocks(consent=True)
        # oauth2_context without app_state: code redirect carries no state.
        claims = dict(mocks["claims"])
        ctx = dict(claims["oauth2_context"])
        ctx["app_state"] = ""
        claims["oauth2_context"] = ctx
        mocks["state_cls"]().verify.return_value = claims
        mocks["state_cls"].get_oauth2_context.return_value = ctx
        resp, _ = _run_callback(patches, mocks)
        assert resp.status_code == 302
        assert "code=authcode-1" in resp.headers["location"]
        assert "state=" not in resp.headers["location"]


def _oauth_storage(client=None):
    storage = MagicMock()
    storage.get_client = AsyncMock(return_value=client)
    return storage


class TestFederatedConsentCheck:
    def test_no_cookie(self):
        from authglow.api import federation as fed_api

        request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
        out = _run(fed_api.federated_consent_check(request, MagicMock()))
        assert out == {"consent_required": False}

    def test_unknown_session(self):
        from authglow.api import federation as fed_api

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "",
                "headers": [(b"cookie", b"__Host-authglow-consent-session=abc")],
            }
        )
        svc = MagicMock()
        svc.get_consent_session = AsyncMock(return_value=None)
        out = _run(fed_api.federated_consent_check(request, svc))
        assert out == {"consent_required": False}

    def test_inactive_client(self):
        from authglow.api import federation as fed_api

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "",
                "headers": [(b"cookie", b"__Host-authglow-consent-session=abc")],
            }
        )
        svc = MagicMock()
        svc.get_consent_session = AsyncMock(return_value={"session_token": "abc", "client_id": "c"})
        svc.delete_consent_session = AsyncMock()
        with patch(
            "authglow.services.oauth_client.OAuth2ClientStorage"
        ) as storage_cls:
            storage_cls().get_client = AsyncMock(return_value=None)
            # The handler constructs OAuth2ClientStorage() directly;
            # patch at the source module instead.
            out = _run(fed_api.federated_consent_check(request, svc))
        assert out == {"consent_required": False}
        svc.delete_consent_session.assert_awaited_once_with("abc")

    def test_success_payload(self):
        from authglow.api import federation as fed_api

        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "",
                "headers": [(b"cookie", b"__Host-authglow-consent-session=abc")],
            }
        )
        svc = MagicMock()
        svc.get_consent_session = AsyncMock(
            return_value={
                "session_token": "abc",
                "client_id": "c",
                "scope": "openid read",
            }
        )
        client = SimpleNamespace(
            client_id="c",
            is_active=True,
            client_name="Web",
            description=None,
            logo_uri=None,
            homepage_uri=None,
            terms_uri=None,
            privacy_uri=None,
            branding=None,
        )
        with patch(
            "authglow.services.oauth_client.OAuth2ClientStorage"
        ) as storage_cls:
            storage_cls().get_client = AsyncMock(return_value=client)
            out = _run(fed_api.federated_consent_check(request, svc))
        assert out["consent_required"] is True
        assert out["client_name"] == "Web"
        assert out["scopes"][0]["name"] == "openid"


class TestAdminProviderCrud:
    def _storage(self, provider=None):
        storage = MagicMock()
        storage.get_provider = AsyncMock(return_value=provider)
        storage.create_provider = AsyncMock(side_effect=lambda p: p)
        storage.list_providers = AsyncMock(return_value=[provider] if provider else [])
        storage.update_provider = AsyncMock(return_value=provider)
        storage.delete_provider = AsyncMock(return_value=True)
        return storage

    def test_create_provider(self):
        from authglow.api import federation as fed_api
        from authglow.models.federation import ExternalIdpConfigCreate

        storage = self._storage()
        out = _run(
            fed_api.create_provider(
                _request(),
                ExternalIdpConfigCreate(
                    label="G", issuer="https://idp.example.com", client_id="c", client_secret="s"
                ),
                _admin(),
                storage,
            )
        )
        assert out.issuer == "https://idp.example.com"
        storage.create_provider.assert_awaited_once()

    def test_create_bad_issuer_400(self):
        from authglow.api import federation as fed_api
        from authglow.models.federation import ExternalIdpConfigCreate

        with pytest.raises(HTTPException) as exc:
            _run(
                fed_api.create_provider(
                    _request(),
                    ExternalIdpConfigCreate(
                        label="G", issuer="ftp://evil", client_id="c", client_secret="s"
                    ),
                    _admin(),
                    self._storage(),
                )
            )
        assert exc.value.status_code == 400

    def test_list_providers(self):
        from authglow.api import federation as fed_api

        out = _run(fed_api.list_all_providers(_admin(), self._storage(_provider())))
        assert len(out) == 1

    def test_get_provider(self):
        from authglow.api import federation as fed_api

        out = _run(fed_api.get_provider("google", _admin(), self._storage(_provider())))
        assert out.id == "google"

    def test_get_provider_404(self):
        from authglow.api import federation as fed_api

        with pytest.raises(HTTPException) as exc:
            _run(fed_api.get_provider("nope", _admin(), self._storage(None)))
        assert exc.value.status_code == 404

    def test_update_provider(self):
        from authglow.api import federation as fed_api
        from authglow.models.federation import ExternalIdpConfigUpdate

        out = _run(
            fed_api.update_provider(
                _request(), "google", ExternalIdpConfigUpdate(label="G2"), _admin(),
                self._storage(_provider()),
            )
        )
        assert out.id == "google"

    def test_update_provider_404(self):
        from authglow.api import federation as fed_api
        from authglow.models.federation import ExternalIdpConfigUpdate

        storage = self._storage(None)
        storage.update_provider = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(
                fed_api.update_provider(
                    _request(), "nope", ExternalIdpConfigUpdate(label="G2"), _admin(), storage
                )
            )
        assert exc.value.status_code == 404

    def test_delete_provider(self):
        from authglow.api import federation as fed_api

        out = _run(fed_api.delete_provider(_request(), "google", _admin(), self._storage()))
        assert out["status"] == "deleted"

    def test_delete_provider_404(self):
        from authglow.api import federation as fed_api

        storage = self._storage()
        storage.delete_provider = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            _run(fed_api.delete_provider(_request(), "nope", _admin(), storage))
        assert exc.value.status_code == 404

    def test_toggle_provider(self):
        from authglow.api import federation as fed_api

        storage = self._storage(_provider(enabled=True))
        out = _run(fed_api.toggle_provider("google", _admin(), storage))
        assert out.id == "google"
        storage.update_provider.assert_awaited_once_with("google", {"enabled": False})

    def test_toggle_provider_404(self):
        from authglow.api import federation as fed_api

        with pytest.raises(HTTPException) as exc:
            _run(fed_api.toggle_provider("nope", _admin(), self._storage(None)))
        assert exc.value.status_code == 404


def _admin():
    from authglow.models.user import User

    return User(id="admin-1", email="admin@example.com", hashed_password="x", scopes=["admin"])
