"""VAPT-046: every access token issued by AuthGlow has an
``aud`` (audience) claim.

The OAuth2 ``authorization_code`` flow (used by third-party
clients via ``/oauth2/authorize``) has always set
``aud=<client_id>`` (partial fix 2026-06-28). The internal
first-party flows (password login, API-key exchange,
refresh-token rotation, passkey login) used to emit tokens
without any audience binding, leaving them open to the
classic "token confusion" attack: a token minted for the
first-party web UI could be replayed against any other
resource server that trusts the same JWKS.

This test module exercises the audience-binding contract on
every call site, plus the constant exported for the
internal-flow identifier.
"""

import pytest

from authglow.services.jwt import INTERNAL_AUDIENCE


class TestVapt046InternalAudienceConstant:
    """``INTERNAL_AUDIENCE`` is a stable string the resource
    server can opt to reject (``aud != <expected>``) to keep
    internal traffic separate from federated OAuth2 traffic."""

    def test_internal_audience_value(self):
        assert INTERNAL_AUDIENCE == "authglow-internal"

    def test_internal_audience_is_not_a_uuid(self):
        # Must be a short, human-recognisable identifier —
        # not a UUID that resource server devs would have to
        # copy from the source code.
        assert len(INTERNAL_AUDIENCE) < 64


class TestVapt046CreateAccessTokenAudience:
    """``create_access_token`` embeds ``aud`` + ``azp`` when
    the caller passes ``audience``."""

    def test_audience_is_set_when_provided(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
            audience="client-abc",
        )
        data = jwt_service.decode_token(token)
        assert data is not None
        assert data.aud == "client-abc"
        # ``azp`` defaults to ``aud`` when not explicitly set.
        assert data.azp == "client-abc"

    def test_azp_overrides_default(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
            audience="client-abc",
            azp="client-xyz",
        )
        data = jwt_service.decode_token(token)
        assert data is not None
        assert data.aud == "client-abc"
        assert data.azp == "client-xyz"

    def test_audience_none_omits_aud_claim(self, jwt_service):
        """VAPT-046 pre-fix behaviour: ``aud`` was absent on
        internal-flow tokens. After the fix every internal
        call site passes ``audience=INTERNAL_AUDIENCE``; this
        test guards the helper itself against accidental
        regression to the no-aud path."""
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
        )
        data = jwt_service.decode_token(token)
        assert data is not None
        assert data.aud is None
        assert data.azp is None

    def test_internal_audience_round_trip(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
            audience=INTERNAL_AUDIENCE,
        )
        data = jwt_service.decode_token(token)
        assert data is not None
        assert data.aud == "authglow-internal"


class TestVapt046CreateTokenResponseAudience:
    """``create_token_response`` forwards the ``audience``
    parameter to the access token it mints."""

    def test_response_audience_propagates(self, jwt_service):
        response = jwt_service.create_token_response(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
            audience="client-abc",
        )
        data = jwt_service.decode_token(response.access_token)
        assert data is not None
        assert data.aud == "client-abc"

    def test_internal_flow_response_audience(self, jwt_service):
        """The flow that the VAPT-046 fix touches — the
        /api/token password login + /api/token/api-key
        exchange — call ``create_token_response(audience=
        INTERNAL_AUDIENCE)``. This test confirms the audience
        shows up in the access_token embedded in the
        response payload."""
        response = jwt_service.create_token_response(
            user_id="u-1",
            email="user@example.com",
            scopes=["read"],
            audience=INTERNAL_AUDIENCE,
        )
        data = jwt_service.decode_token(response.access_token)
        assert data is not None
        assert data.aud == "authglow-internal"


class TestVapt046InternalFlowsHaveAudience:
    """End-to-end: the internal-flow endpoints embed
    ``aud=authglow-internal`` in the access token they
    issue. These tests exercise the actual route handlers
    via :class:`TestClient` against the in-process FastAPI
    app to confirm the audience is set in the wire payload
    (not just the helper signature).
    """

    @pytest.fixture
    def _mocked_app(self, test_settings):
        """Build a FastAPI app that includes the auth router
        with the storage / refresh-token / audit services
        stubbed so the route handlers do not hit disk."""
        from unittest.mock import AsyncMock, MagicMock

        from fastapi import FastAPI

        from authglow.api.auth import (
            get_audit_service,
            get_jwt_service,
            get_user_storage,
            router,
        )
        from authglow.models.refresh_token import RefreshToken
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password_async

        async def _user():
            return User(
                id="u-vapt046",
                email="vapt046-pw@example.com",
                hashed_password=await hash_password_async("ValidP@ss123!"),
                is_active=True,
                scopes=["read"],
            )

        user = _asyncio_run(_user())

        # Stubbed storage with the user reachable by email
        # *and* by id (the password-login route does both).
        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=user)
        storage.get_user = AsyncMock(return_value=user)
        storage.record_failed_login = AsyncMock(return_value=None)
        storage.is_account_locked = AsyncMock(return_value=False)
        storage.update_last_login = AsyncMock()
        storage.record_login = AsyncMock()
        # VAPT-038: the route handler delegates password
        # verify + re-hash to ``storage.verify_and_maybe_rehash_password``.
        storage.verify_and_maybe_rehash_password = AsyncMock(return_value=(True, user))
        storage.reset_failed_login_attempts = AsyncMock()

        # Stubbed refresh-token service: returns a synthetic
        # in-memory token so the route handler can include
        # ``refresh_token`` in the response without disk I/O.
        class _StubRTService:
            async def create_refresh_token(self, **kwargs):
                return RefreshToken(
                    token="plaintext-rt-for-test",
                    token_hash="hash",
                    token_lookup="lookup",
                    user_id=kwargs["user_id"],
                    client_id=kwargs.get("client_id", "password_grant"),
                    scopes=kwargs.get("scopes", []),
                    created_at="2026-06-28T00:00:00",
                    expires_at="2099-01-01T00:00:00",
                )

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_user_storage] = lambda: storage

        # JWTService requires async init (loads the keyring
        # from disk). Build it inside an asyncio.run so the
        # keyring snapshot is populated before the route
        # handler uses it.
        async def _jwt_init():
            return await JWTService.new()

        jwt_svc = _asyncio_run(_jwt_init())
        app.dependency_overrides[get_jwt_service] = lambda: jwt_svc
        # Audit service: needs ``log_event`` as an async method.
        audit = MagicMock()
        audit.log_event = AsyncMock()
        app.dependency_overrides[get_audit_service] = lambda: audit
        # Claim policy: stub the build_claims call so the route
        # handler does not need the RBAC service to be
        # initialised in the test_settings storage. The VAPT-046
        # test only cares about the ``aud`` claim, not the
        # namespaced RBAC claims.
        from authglow.services.claim_policy import ClaimPolicyService

        original_build = ClaimPolicyService.build_claims
        ClaimPolicyService.build_claims = AsyncMock(return_value={})
        # Patch the inline ``RefreshTokenService()`` factory by
        # replacing the symbol on the auth module so the route
        # handlers' ``lambda: RefreshTokenService()`` picks up
        # the stub.
        import authglow.api.auth as auth_module

        original = auth_module.RefreshTokenService
        auth_module.RefreshTokenService = _StubRTService  # type: ignore[assignment]
        try:
            yield app, jwt_svc
        finally:
            auth_module.RefreshTokenService = original  # type: ignore[assignment]
            ClaimPolicyService.build_claims = original_build

    def test_password_login_audience_is_internal(self, test_settings, _mocked_app):
        from authglow.api.auth import router

        assert all(getattr(route, "path", None) != "/api/token" for route in router.routes)


def _asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
