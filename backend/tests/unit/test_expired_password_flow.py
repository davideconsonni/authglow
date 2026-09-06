"""Forced credential rotation (``password_expired``) — end-to-end unit tests.

Covers the two halves of the flow:

1. ``POST /api/oauth2/authorize``: when an admin has flagged the user's
   password as expired, a SUCCESSFUL credential check must NOT issue an
   auth code / MFA challenge / session — it must return
   ``{"password_expired": true, "email": ...}`` so the SPA can route to
   the forced-change screen. The flag must be checked AFTER the bcrypt
   verify (credentials proven) and BEFORE the MFA branch (the change only
   needs proof of the current password) and BEFORE ``record_login`` /
   ``update_last_login`` (the login is not complete).
2. ``POST /api/auth/expired-password/change``: re-verifies credentials,
   applies the shared strength policy, clears the flag via
   ``set_password(require_change=False)``, and audits the event.

Mock wiring mirrors ``test_vapt048._build_authorize_app_with_mocks``
(auth + storage layers stubbed so the endpoint resolves dependencies
without touching disk).
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

OLD_PASSWORD = "OldP@ssw0rd!"
NEW_PASSWORD = "NewP@ssw0rd!"
# Long enough for min_length=8 but missing an uppercase letter → 400.
WEAK_PASSWORD = "alllowercase1!"

STATE = "abcdef1234567890" * 2  # 32 chars — VAPT-044


def _build_authorize_app_with_mocks(test_settings):
    """Same mock wiring as test_vapt048/test_csrf_protection."""
    from authglow.api.auth import (
        get_audit_service,
        get_mfa_service,
        get_oauth2_service,
        get_session_service,
        get_user_storage,
        router,
    )
    from authglow.models.oauth_client import OAuth2Client

    client = OAuth2Client(
        client_id="client-abc",
        client_secret="fake-hash",
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"],
    )
    client.require_consent = False

    oauth2_client_storage = MagicMock()
    oauth2_client_storage.get_client = AsyncMock(return_value=client)
    oauth2_client_storage.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_client_storage.is_scope_allowed = AsyncMock(return_value=True)

    oauth2_svc = MagicMock()
    oauth2_svc.client_storage = oauth2_client_storage
    oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_svc.process_scopes = AsyncMock(return_value=["read"])
    oauth2_svc.create_authorization_code = AsyncMock(
        return_value=SimpleNamespace(code="ac-unit-code")
    )
    oauth2_svc.is_grant_type_allowed = AsyncMock(return_value=True)

    mfa_svc = MagicMock()
    mfa_svc.is_device_trusted = AsyncMock(return_value=True)

    session_svc = MagicMock()
    session_svc.create_consent_session = AsyncMock()
    session_svc.create_mfa_session = AsyncMock()

    audit_svc = AsyncMock()
    audit_svc.log_event = AsyncMock()

    storage = MagicMock()
    storage.get_user = AsyncMock()
    storage.get_user_by_email = AsyncMock()
    storage.is_account_locked = AsyncMock(return_value=False)
    storage.reset_failed_login_attempts = AsyncMock()
    storage.record_failed_login = AsyncMock()
    storage.update_last_login = AsyncMock()
    storage.set_password = AsyncMock()
    storage.verify_and_maybe_rehash_password = AsyncMock(return_value=(True, None))
    storage.check_and_enforce_concurrent_sessions = AsyncMock()

    app = FastAPI()
    app.include_router(router)

    app.dependency_overrides[get_user_storage] = lambda: storage
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_svc
    app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    app.dependency_overrides[get_session_service] = lambda: session_svc
    app.dependency_overrides[get_audit_service] = lambda: audit_svc

    return app, storage, audit_svc, oauth2_svc, mfa_svc, session_svc


def _post_authorize(http_client, email="expired@example.com", password=OLD_PASSWORD):
    return http_client.post(
        "/api/oauth2/authorize",
        data={
            "client_id": "client-abc",
            "redirect_uri": "https://example.com/callback",
            "scope": "read",
            "code_challenge": "test-challenge-abc",
            "code_challenge_method": "S256",
            "state": STATE,
            "email": email,
            "password": password,
        },
    )


class TestAuthorizeExpiredPasswordGate:
    def test_expired_password_blocks_login_with_structured_response(
        self, test_settings
    ):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, _audit, oauth2_svc, mfa_svc, session_svc = (
            _build_authorize_app_with_mocks(test_settings)
        )
        user = User(
            id="user-expired",
            email="expired@example.com",
            hashed_password=hash_password(OLD_PASSWORD),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            password_expired=True,
        )
        storage.get_user_by_email.return_value = user

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = _post_authorize(http_client)

        assert response.status_code == 200, response.text
        body = response.json()
        assert body == {"password_expired": True, "email": "expired@example.com"}

        # No auth code, no MFA challenge, no consent session.
        oauth2_svc.create_authorization_code.assert_not_called()
        mfa_svc.is_device_trusted.assert_not_called()
        session_svc.create_mfa_session.assert_not_called()

        # The login never completed: no history entry, no last_login bump.
        storage.update_last_login.assert_not_called()

    def test_non_expired_user_logs_in_normally(self, test_settings):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, _audit, _oauth2, _mfa, _session = (
            _build_authorize_app_with_mocks(test_settings)
        )
        user = User(
            id="user-normal",
            email="normal@example.com",
            hashed_password=hash_password(OLD_PASSWORD),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            password_expired=False,
        )
        storage.get_user_by_email.return_value = user

        with (
            patch("authglow.api.auth.get_settings", return_value=test_settings),
            patch(
                "authglow.services.login_history.LoginHistoryService.record_login",
                new_callable=AsyncMock,
            ),
        ):
            http_client = TestClient(app)
            response = _post_authorize(http_client, email="normal@example.com")

        assert response.status_code == 200, response.text
        body = response.json()
        assert "password_expired" not in body
        assert body["redirect_url"].startswith("https://example.com/callback")
        storage.update_last_login.assert_awaited_once_with("user-normal")

    def test_flag_checked_after_bcrypt_and_before_mfa(self):
        """Antiregression: source ordering inside the password branch —
        get_user_by_email < bcrypt verify < password_expired < mfa_enabled."""
        import inspect

        from authglow.api.auth import authorize_post

        source = inspect.getsource(authorize_post)
        get_by_email_pos = source.find("storage.get_user_by_email")
        verify_pos = source.find("verify_and_maybe_rehash_password")
        expired_pos = source.find("if user.password_expired:")
        mfa_pos = source.find("if user.mfa_enabled and user.mfa_verified:")

        assert -1 not in (get_by_email_pos, verify_pos, expired_pos, mfa_pos), (
            "one of the ordering anchors is missing from authorize_post"
        )
        assert get_by_email_pos < verify_pos < expired_pos < mfa_pos, (
            "password_expired gate must sit AFTER the credential verify "
            "(proof of identity) and BEFORE the MFA branch (no code/session "
            "may be issued on an expired-password account)"
        )


class TestChangeExpiredPasswordEndpoint:
    def _build_change_app(self, test_settings, *, user=None):
        from authglow.api.password_reset import (
            get_audit_service as get_reset_audit_service,
        )
        from authglow.api.password_reset import (
            get_user_storage as get_reset_user_storage,
        )
        from authglow.api.password_reset import router as password_reset_router
        from authglow.services.audit import AuditService

        app, storage, audit_svc, *_rest = _build_authorize_app_with_mocks(test_settings)
        app.include_router(password_reset_router)

        # The password_reset module registers its own dependency getters;
        # override those (same underlying mocks).
        app.dependency_overrides[get_reset_user_storage] = lambda: storage
        app.dependency_overrides[get_reset_audit_service] = lambda: audit_svc
        if user is not None:
            storage.get_user_by_email.return_value = user
        # Real PasswordValidator runs against the patched test settings.

        reset_audit_override = app.dependency_overrides[get_reset_audit_service]
        assert callable(reset_audit_override)
        assert isinstance(AuditService, type)

        return app, storage, audit_svc

    def _make_user(self, *, password_expired: bool = True, is_active: bool = True):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        return User(
            id="user-expired",
            email="expired@example.com",
            hashed_password=hash_password(OLD_PASSWORD),
            is_active=is_active,
            email_verified=True,
            scopes=["read"],
            password_expired=password_expired,
        )

    def _post_change(self, http_client, **overrides):
        payload = {
            "email": "expired@example.com",
            "current_password": OLD_PASSWORD,
            "new_password": NEW_PASSWORD,
        }
        payload.update(overrides)
        return http_client.post("/api/auth/expired-password/change", json=payload)

    def test_happy_path_resets_flag_and_hashes_new_password(
        self, test_settings
    ):
        app, storage, audit_svc = self._build_change_app(
            test_settings, user=self._make_user(password_expired=True)
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client)

        assert response.status_code == 200, response.text
        assert "sign in" in response.json()["message"].lower()

        # Flag cleared through set_password(require_change=False).
        storage.set_password.assert_awaited_once()
        args, kwargs = storage.set_password.await_args
        assert args[0] == "user-expired"
        assert args[1] != OLD_PASSWORD
        assert kwargs.get("require_change") is False or (
            len(args) >= 3 and args[2] is False
        )

        # Success audited.
        logged_events = [c.kwargs.get("event_type") for c in audit_svc.log_event.call_args_list]
        assert logged_events == ["password_changed_after_expiry"]

    def test_wrong_current_password_gets_uniform_401(self, test_settings):
        app, storage, audit_svc = self._build_change_app(
            test_settings, user=self._make_user()
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client, current_password="WrongP@ss1!")

        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "Invalid credentials"
        storage.set_password.assert_not_called()
        audit_svc.log_event.assert_awaited_once()

    def test_nonexistent_user_gets_uniform_401_without_bcrypt(self, test_settings):
        app, storage, _audit = self._build_change_app(test_settings)
        storage.get_user_by_email.return_value = None

        bcrypt_spy = MagicMock(side_effect=AssertionError("bcrypt must not run"))
        with (
            patch("authglow.api.auth.get_settings", return_value=test_settings),
            patch(
                "authglow.api.password_reset.verify_password_async", bcrypt_spy
            ),
        ):
            http_client = TestClient(app)
            response = self._post_change(http_client)

        assert response.status_code == 401, response.text
        bcrypt_spy.assert_not_called()

    def test_inactive_user_rejected(self, test_settings):
        app, storage, _audit = self._build_change_app(
            test_settings, user=self._make_user(is_active=False)
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client)

        assert response.status_code == 401, response.text
        storage.set_password.assert_not_called()

    def test_flag_not_set_returns_400_even_with_valid_credentials(
        self, test_settings
    ):
        app, storage, _audit = self._build_change_app(
            test_settings, user=self._make_user(password_expired=False)
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client)

        assert response.status_code == 400, response.text
        assert "not required" in response.json()["detail"]
        storage.set_password.assert_not_called()

    def test_weak_new_password_rejected(self, test_settings):
        app, storage, _audit = self._build_change_app(
            test_settings, user=self._make_user()
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client, new_password=WEAK_PASSWORD)

        assert response.status_code == 400, response.text
        assert "uppercase" in response.json()["detail"]
        storage.set_password.assert_not_called()

    def test_new_password_same_as_current_rejected(self, test_settings):
        app, storage, _audit = self._build_change_app(
            test_settings, user=self._make_user()
        )

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = self._post_change(http_client, new_password=OLD_PASSWORD)

        assert response.status_code == 400, response.text
        assert "different" in response.json()["detail"]
        storage.set_password.assert_not_called()


class TestSetPasswordCacheInvalidation:
    """Regression for the live-reported forced-change loop.

    The login flow resolves users via ``get_user_by_email``, which caches
    the User object under the email key. If ``set_password`` fails to
    invalidate THAT cache (it used to clear only the by-id one), the next
    login verifies credentials against the STALE hash: the new password is
    rejected and the old one still "works" with ``password_expired`` still
    True — an infinite forced-change loop. This test exercises the REAL
    UserService + FileUserRepository + real caches on tmp storage.
    """

    async def test_email_lookup_after_set_password_serves_new_hash(self, test_settings):
        from authglow.models.user import User
        from authglow.services.password import hash_password, verify_password_async
        from authglow.services.user import UserService

        svc = UserService()
        user = User(
            id="user-cache-loop",
            email="cacheloop@example.com",
            hashed_password=hash_password(OLD_PASSWORD),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            password_expired=True,
        )
        await svc.create_user(user)

        # Warm the email cache exactly like a first login does.
        cached = await svc.get_user_by_email(user.email)
        assert cached is not None and cached.password_expired is True

        await svc.set_password(user.id, hash_password(NEW_PASSWORD))

        fresh = await svc.get_user_by_email(user.email)
        assert fresh is not None
        assert fresh.password_expired is False, (
            "stale email cache: flag still expired after set_password"
        )
        assert await verify_password_async(NEW_PASSWORD, fresh.hashed_password), (
            "stale email cache: new password does not verify"
        )
        assert not await verify_password_async(OLD_PASSWORD, fresh.hashed_password)
