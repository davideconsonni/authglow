"""End-to-end repro of the user-reported MFA login failure.

Simulates EXACTLY what the browser does (fresh ``data/`` dir, like the
user's wiped state):

1.  Create user (registration).
2.  Login via ``POST /api/oauth2/authorize`` (email+password, PKCE) — no
    MFA yet → expect auth code / redirect.
3.  Enroll MFA via ``POST /api/mfa/enroll`` (Bearer JWT) → get secret.
4.  Verify enrollment via ``POST /api/mfa/verify`` with a fresh TOTP.
5.  Fresh login via ``POST /api/oauth2/authorize`` → expect
    ``{"mfa_required": True, "session_token": ...}``.
6.  ``POST /api/mfa/verify-oauth-login`` with a fresh TOTP →
    **this is where the user always sees "Invalid code"**.
7.  Second fresh login → verify with a BACKUP code.

All services are REAL (file-backed storage on tmp dir, real crypto,
real TOTP). The only mock is the audit sink. If step 6 returns
anything but 200, the bug reproduces and the response body + status
(not masked by the frontend's generic message) tells us WHY.
"""

import asyncio
import secrets
from unittest.mock import AsyncMock, MagicMock

import pyotp
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api import auth as auth_mod
from authglow.api import mfa as mfa_mod


def _build_e2e_app(
    test_settings,
    storage,
    jwt_service,
    mfa_service,
    session_service,
    persist_first_party_client: bool = True,
):
    from authglow.services.oauth2 import OAuth2Service

    app = FastAPI()
    app.include_router(auth_mod.router)
    app.include_router(mfa_mod.router)

    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock()
    mock_api_key = MagicMock()

    # Mirror production bootstrap: since the startup auto-persistence
    # (``ensure_first_party_client``) the first-party dashboard client is
    # a normal persisted client. Tests that mirror a *fresh* deployment
    # (empty oauth_clients dir) must run the ensure step explicitly —
    # there is no settings-derived fallback anymore in
    # verify_oauth_mfa_login, a missing client is a real error.
    from unittest.mock import patch

    from authglow.api.auth import _first_party_oauth_client
    from authglow.services.oauth_client import OAuth2ClientStorage

    if persist_first_party_client:
        with patch("authglow.services.oauth_client.get_settings", return_value=test_settings):
            client_storage = OAuth2ClientStorage()
            fp = _first_party_oauth_client(test_settings)
            asyncio.run(client_storage.create_client(fp, "first-party-public-client"))

    oauth2_svc = OAuth2Service()

    app.dependency_overrides[auth_mod.get_user_storage] = lambda: storage
    app.dependency_overrides[mfa_mod.get_user_storage] = lambda: storage
    app.dependency_overrides[auth_mod.get_jwt_service] = lambda: jwt_service
    app.dependency_overrides[auth_mod.get_oauth2_service] = lambda: oauth2_svc
    app.dependency_overrides[auth_mod.get_mfa_service] = lambda: mfa_service
    app.dependency_overrides[auth_mod.get_session_service] = lambda: session_service
    app.dependency_overrides[auth_mod.get_audit_service] = lambda: mock_audit
    app.dependency_overrides[mfa_mod.get_mfa_service] = lambda: mfa_service
    app.dependency_overrides[mfa_mod.get_audit_service] = lambda: mock_audit
    app.dependency_overrides[auth_mod.get_api_key_service] = lambda: mock_api_key

    return TestClient(app)


def _authorize_data(test_settings, email, password):
    return {
        "email": email,
        "password": password,
        "client_id": test_settings.oauth2_client_id,
        "redirect_uri": test_settings.oauth2_first_party_redirect_uri,
        "response_type": "code",
        "scope": "read",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "state": secrets.token_urlsafe(32),
    }


class TestMFALoginEndToEnd:
    def test_full_browser_flow_totp(
        self, test_settings, storage, jwt_service, mfa_service, session_service
    ):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        client = _build_e2e_app(test_settings, storage, jwt_service, mfa_service, session_service)

        email = "e2e@example.com"
        password = "TestP@ss123!"
        user = User(
            id="e2e-user-001",
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
            email_verified=True,
            scopes=["read", "write"],
        )
        asyncio.run(storage.create_user(user))

        # 2. Login without MFA → should get an auth code redirect, no MFA gate.
        r = client.post(
            "/api/oauth2/authorize", data=_authorize_data(test_settings, email, password)
        )
        assert r.status_code == 200, f"pre-MFA login failed: {r.status_code} {r.text}"
        assert "mfa_required" not in r.json(), r.json()

        # 3. Enroll MFA.
        access = jwt_service.create_access_token(user.id, email, ["read", "write"])
        r = client.post("/api/mfa/enroll", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200, f"enroll failed: {r.status_code} {r.text}"
        enroll = r.json()
        secret = enroll["secret"]
        assert secret, "enroll must return a TOTP secret"

        # 4. Verify enrollment with a fresh TOTP code.
        r = client.post(
            "/api/mfa/verify",
            headers={"Authorization": f"Bearer {access}"},
            json={"code": pyotp.TOTP(secret).now()},
        )
        assert r.status_code == 200, f"enroll-verify failed: {r.status_code} {r.text}"

        fresh = asyncio.run(storage.get_user(user.id))
        assert fresh.mfa_enabled is True and fresh.mfa_verified is True

        # 5. Fresh login → must hit the MFA gate.
        r = client.post(
            "/api/oauth2/authorize", data=_authorize_data(test_settings, email, password)
        )
        assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
        body = r.json()
        assert body.get("mfa_required") is True, f"expected MFA gate, got: {body}"
        mfa_session = body["session_token"]

        # 6. THE USER'S SYMPTOM: verify with a CORRECT, fresh TOTP code.
        r = client.post(
            "/api/mfa/verify-oauth-login",
            json={"session_token": mfa_session, "code": pyotp.TOTP(secret).now()},
        )
        assert r.status_code == 200, (
            f"BUG REPRODUCED — login MFA rejected a valid TOTP: "
            f"status={r.status_code} body={r.text}"
        )
        assert "redirect_url" in r.json(), r.json()

    def test_totp_first_party_client_autopersisted_at_boot(
        self, test_settings, storage, jwt_service, mfa_service, session_service
    ):
        """Regression: the first-party client is auto-persisted at startup.

        Mirrors the real playground deployment that surfaced the bug:
        ``data/users/oauth_clients`` is empty on first boot. The lifespan
        (``ensure_first_party_client``) must create the client as a normal
        persisted row, so the strict repository lookup in
        ``verify_oauth_mfa_login`` succeeds for a valid TOTP. Before the
        fix this flow failed with HTTP 400 "Invalid or inactive OAuth
        client" (the endpoint was the only one without the settings
        fallback), and the SPA masked it as "Invalid code".
        """
        from authglow.models.user import User
        from authglow.services.oauth_client import ensure_first_party_client
        from authglow.services.password import hash_password

        client = _build_e2e_app(
            test_settings,
            storage,
            jwt_service,
            mfa_service,
            session_service,
            persist_first_party_client=False,
        )

        # Startup bootstrap: create-if-missing, idempotent. The
        # cross-request oauth client cache is process-global and may
        # hold the same client_id from a sibling test with a different
        # data dir — evict it to mirror a fresh boot.
        from authglow.core.cache import oauth_client_cache

        asyncio.run(oauth_client_cache.delete(test_settings.oauth2_client_id))
        created = asyncio.run(ensure_first_party_client(test_settings))
        assert created is True, "boot ensure must create the first-party client"
        created_again = asyncio.run(ensure_first_party_client(test_settings))
        assert created_again is False, "boot ensure must be idempotent"

        # The persisted client is a normal row, readable via strict lookup.
        from authglow.services.oauth_client import OAuth2ClientStorage

        persisted = asyncio.run(
            OAuth2ClientStorage(settings=test_settings).get_client(test_settings.oauth2_client_id)
        )
        assert persisted is not None and persisted.is_active, (
            "first-party client must be persisted and active after boot"
        )

        email = "e2e-noclient@example.com"
        password = "TestP@ss123!"
        user = User(
            id="e2e-user-003",
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
            email_verified=True,
            scopes=["read", "write"],
        )
        asyncio.run(storage.create_user(user))

        access = jwt_service.create_access_token(user.id, email, ["read", "write"])
        r = client.post("/api/mfa/enroll", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200, f"enroll failed: {r.status_code} {r.text}"
        secret = r.json()["secret"]

        r = client.post(
            "/api/mfa/verify",
            headers={"Authorization": f"Bearer {access}"},
            json={"code": pyotp.TOTP(secret).now()},
        )
        assert r.status_code == 200, f"enroll-verify failed: {r.status_code} {r.text}"

        r = client.post(
            "/api/oauth2/authorize", data=_authorize_data(test_settings, email, password)
        )
        assert r.status_code == 200, r.text
        assert r.json().get("mfa_required") is True, r.json()

        r = client.post(
            "/api/mfa/verify-oauth-login",
            json={
                "session_token": r.json()["session_token"],
                "code": pyotp.TOTP(secret).now(),
            },
        )
        assert r.status_code == 200, (
            f"REGRESSION — MFA rejected a valid TOTP when the first-party "
            f"client is not persisted: status={r.status_code} body={r.text}"
        )
        assert "redirect_url" in r.json(), r.json()

    def test_full_browser_flow_backup_code(
        self, test_settings, storage, jwt_service, mfa_service, session_service
    ):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        client = _build_e2e_app(test_settings, storage, jwt_service, mfa_service, session_service)

        email = "e2e-bak@example.com"
        password = "TestP@ss123!"
        user = User(
            id="e2e-user-002",
            email=email,
            hashed_password=hash_password(password),
            is_active=True,
            email_verified=True,
            scopes=["read", "write"],
        )
        asyncio.run(storage.create_user(user))

        access = jwt_service.create_access_token(user.id, email, ["read", "write"])
        r = client.post("/api/mfa/enroll", headers={"Authorization": f"Bearer {access}"})
        assert r.status_code == 200, r.text
        enroll = r.json()
        backup_code = enroll["backup_codes"][0]

        r = client.post(
            "/api/mfa/verify",
            headers={"Authorization": f"Bearer {access}"},
            json={"code": pyotp.TOTP(enroll["secret"]).now()},
        )
        assert r.status_code == 200, r.text

        r = client.post(
            "/api/oauth2/authorize", data=_authorize_data(test_settings, email, password)
        )
        assert r.status_code == 200, r.text
        assert r.json().get("mfa_required") is True, r.json()

        r = client.post(
            "/api/mfa/verify-oauth-login",
            json={"session_token": r.json()["session_token"], "code": backup_code},
        )
        assert r.status_code == 200, (
            f"BUG REPRODUCED — login MFA rejected a valid BACKUP code: "
            f"status={r.status_code} body={r.text}"
        )
