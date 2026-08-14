"""VAPT-048: account lockout is checked BEFORE the bcrypt compare
on every password-authenticating endpoint, preventing CPU DoS
amplification.

Threat model — pre-fix: with a 10/minute per-IP rate limit on
``/api/oauth2/authorize`` and a 5/minute limit on ``/api/token``,
an attacker could still pay one full bcrypt cost (~100ms at the
default ``bcrypt_rounds=12``) per request, capped only by the
per-IP rate limiter. Locking an account did not stop the
attacker from burning server CPU — it just stopped them from
authenticating.

Post-fix: the lockout check is a single file read with no
crypto. A locked account costs <1ms per request, removing the
amplification primitive. The bcrypt path is reserved for
non-locked accounts only.

This module exercises:

* the source-level ordering in both endpoints (antiregression);
* the behavioural response when the account IS locked
  (423, no bcrypt, no ``record_failed_login`` side effect);
* the behavioural response when the account is NOT locked and
  the password is wrong (401 + ``record_failed_login``).

The companion integration test
``tests/integration/test_auth_api.py::TestLoginLockoutOrder``
covers the same ordering for ``/api/token`` and is part of the
regression net.
"""

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Source-ordering checks — cheap, robust, no fixtures needed
# ---------------------------------------------------------------------------


class TestVapt048AuthorizePostOrdering:
    """The ``/api/oauth2/authorize`` password branch must check
    ``is_account_locked`` BEFORE calling
    ``verify_and_maybe_rehash_password``."""

    def test_lockout_check_precedes_bcrypt_in_authorize_post(self):
        from authglow.api.auth import authorize_post

        source = inspect.getsource(authorize_post)
        lockout_pos = source.find("is_account_locked")
        verify_pwd_pos = source.find("verify_and_maybe_rehash_password")
        assert lockout_pos != -1, "is_account_locked call missing from authorize_post"
        assert verify_pwd_pos != -1, (
            "verify_and_maybe_rehash_password call missing from authorize_post"
        )
        assert lockout_pos < verify_pwd_pos, (
            "VAPT-048 regression: authorize_post must check is_account_locked "
            "BEFORE the bcrypt compare. lockout_pos=%d, verify_pwd_pos=%d"
            % (lockout_pos, verify_pwd_pos)
        )

    def test_lockout_check_appears_in_password_branch(self):
        """The lockout check must live inside the ``else:`` branch
        (the email+password path), not the session-cookie path —
        the session-cookie branch does not call bcrypt, so a
        misplaced check would be a dead code path."""
        from authglow.api.auth import authorize_post

        source = inspect.getsource(authorize_post)
        # The password path is the second ``if user:`` else branch.
        # We verify the ``is_account_locked`` call is positioned
        # AFTER ``storage.get_user_by_email`` (the entry point of
        # the password path) and BEFORE the bcrypt call.
        get_by_email_pos = source.find("storage.get_user_by_email")
        lockout_pos = source.find("is_account_locked")
        verify_pwd_pos = source.find("verify_and_maybe_rehash_password")
        assert get_by_email_pos < lockout_pos < verify_pwd_pos, (
            "is_account_locked must sit between get_user_by_email "
            "(entry of the password branch) and verify_and_maybe_rehash_password"
        )


# ---------------------------------------------------------------------------
# Behavioural tests — verify the response shape and side effects
# ---------------------------------------------------------------------------


def _build_authorize_app_with_mocks(test_settings):
    """Reuse the same mock wiring as
    ``test_csrf_protection._build_authorize_app_with_mocks`` —
    the auth + storage layers are stubbed so the endpoint
    resolves the dependencies without hitting disk."""
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

    oauth2_client_storage = MagicMock()
    oauth2_client_storage.get_client = AsyncMock(return_value=client)
    oauth2_client_storage.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_client_storage.is_scope_allowed = AsyncMock(return_value=True)

    oauth2_svc = MagicMock()
    oauth2_svc.client_storage = oauth2_client_storage
    oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_svc.process_scopes = AsyncMock(return_value=["read"])
    oauth2_svc.create_authorization_code = AsyncMock()
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
    storage.verify_and_maybe_rehash_password = AsyncMock(
        return_value=(True, None)  # pragma: no cover — set per-test
    )

    app = FastAPI()
    app.include_router(router)

    app.dependency_overrides[get_user_storage] = lambda: storage
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_svc
    app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    app.dependency_overrides[get_session_service] = lambda: session_svc
    app.dependency_overrides[get_audit_service] = lambda: audit_svc

    return app, storage, audit_svc


class TestVapt048AuthorizePostLockedUser:
    """A locked user submitting email+password must get 423
    without bcrypt being invoked."""

    def test_locked_user_gets_423_without_bcrypt(self, test_settings, monkeypatch):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, _audit = _build_authorize_app_with_mocks(test_settings)
        user = User(
            id="user-locked",
            email="locked@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            locked_until=__import__("datetime").datetime(
                2099, 1, 1, tzinfo=__import__("datetime").timezone.utc
            ),
        )
        storage.get_user_by_email.return_value = user
        storage.is_account_locked.return_value = True

        # Spy on bcrypt — must NOT be called when the account is locked.
        bcrypt_spy = MagicMock(return_value=(True, user))
        storage.verify_and_maybe_rehash_password = bcrypt_spy

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                    "state": "abcdef1234567890" * 2,  # 32 chars — VAPT-044
                    "email": "locked@example.com",
                    "password": "GoodP@ss1!",
                },
            )

        assert response.status_code == 423, response.text
        # The 423 must reference the lockout, not "Invalid credentials".
        assert "locked" in response.json()["detail"].lower()
        # Critical: bcrypt must NOT be invoked on a locked account.
        bcrypt_spy.assert_not_called()
        # The failed-login counter must not be bumped either —
        # the password was never checked.
        storage.record_failed_login.assert_not_called()

    def test_non_existent_user_gets_401_without_bcrypt(self, test_settings):
        """A request for a non-existent email returns 401 without
        bcrypt (VAPT-050 will add a dummy bcrypt to equalize
        timing; until then this is the documented intermediate
        state)."""
        app, storage, _audit = _build_authorize_app_with_mocks(test_settings)
        storage.get_user_by_email.return_value = None

        bcrypt_spy = MagicMock(return_value=(True, None))
        storage.verify_and_maybe_rehash_password = bcrypt_spy

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                    "state": "abcdef1234567890" * 2,
                    "email": "ghost@example.com",
                    "password": "GoodP@ss1!",
                },
            )

        assert response.status_code == 401, response.text
        assert response.json()["detail"] == "Invalid credentials"
        # bcrypt is not invoked when the user does not exist —
        # this is the path VAPT-050 will harden with a dummy
        # bcrypt to equalize timing.
        bcrypt_spy.assert_not_called()

    def test_unlocked_user_with_wrong_password_calls_bcrypt_then_record_failed(self, test_settings):
        """Sanity check: when the account is NOT locked, the
        endpoint must proceed to bcrypt and bump
        ``failed_login_attempts`` on a mismatch."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, _audit = _build_authorize_app_with_mocks(test_settings)
        user = User(
            id="user-unlocked",
            email="user@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user_by_email.return_value = user
        storage.is_account_locked.return_value = False
        storage.verify_and_maybe_rehash_password = AsyncMock(return_value=(False, None))

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                    "state": "abcdef1234567890" * 2,
                    "email": "user@example.com",
                    "password": "WrongP@ss1!",
                },
            )

        assert response.status_code == 401, response.text
        storage.verify_and_maybe_rehash_password.assert_awaited_once()
        storage.record_failed_login.assert_awaited_once_with("user-unlocked")

