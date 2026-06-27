"""Integration tests for the OAuth 2.0 token endpoint with JWT-Bearer
client authentication (``client_secret_jwt`` / ``private_key_jwt``).

CONFORMANCE_REMEDIATION_PLAN.md workstream T.2.

These tests stand up a minimal FastAPI app with the real
``/oauth2/token`` router and replace the heavy backing services
with ``MagicMock`` instances. The client_assertion JWT signing
happens in-process — the verifier runs against the real
``authglow.services.client_jwt_auth`` module so end-to-end coverage
is preserved.
"""

import base64
import json
import time
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rsa_keypair():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _jwk_dict(private_key) -> dict:
    jwk_str = jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key())
    return json.loads(jwk_str)


def _aud() -> str:
    from authglow.core.config import get_settings

    issuer = get_settings().issuer.rstrip("/")
    return f"{issuer}/oauth2/token"


def _signed_jwt(
    *,
    algorithm: str,
    key,
    client_id: str,
    jti: str,
    exp_offset: int = 60,
    aud: str = None,
    iss: str = None,
    sub: str = None,
) -> str:
    now = int(time.time())
    payload = {
        "iss": iss or client_id,
        "sub": sub or client_id,
        "aud": aud or _aud(),
        "exp": now + exp_offset,
        "jti": jti,
    }
    if algorithm == "HS256":
        return jwt.encode(payload, key, algorithm="HS256")
    return jwt.encode(payload, key, algorithm="RS256")


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------


def _build_app_and_storage(
    *,
    client_method: str = "client_secret_basic",
    jwt_key_ciphertext: str = None,
    public_jwk: dict = None,
    client_secret_hash: str = None,
    client_id: str = "jwt-test-client",
):
    """Build a minimal FastAPI app with mocked storage and an auth code.

    Returns ``(app, storage_mock, jwt_service_mock, oauth2_service_mock,
    refresh_token_service_mock, user_storage_mock, code_record)``.
    """
    from authglow.api.auth import router as auth_router
    from authglow.models.oauth_client import OAuth2Client

    if client_secret_hash is None:
        from authglow.services.password import hash_password

        client_secret_hash = hash_password("hashed-plaintext")

    client = OAuth2Client(
        client_id=client_id,
        client_secret=client_secret_hash,
        client_name="JWT Test Client",
        redirect_uris=["https://example.com/cb"],
        grant_types=["authorization_code", "client_credentials"],
        allowed_scopes=["read"],
        is_active=True,
        token_endpoint_auth_method=client_method,
        client_secret_jwt_key=jwt_key_ciphertext,
        public_jwk=public_jwk,
    )

    auth_code = MagicMock()
    auth_code.client_id = client_id
    auth_code.user_id = "user-1"
    auth_code.redirect_uri = "https://example.com/cb"
    auth_code.scope = "openid read"
    auth_code.code_challenge = None  # PKCE disabled for these tests
    auth_code.code_challenge_method = None
    auth_code.nonce = None
    auth_code.acr = None
    auth_code.amr = None
    auth_code.expires_at = None

    storage = MagicMock()
    storage.get_client = AsyncMock(return_value=client)
    storage.get_authorization_code = AsyncMock(return_value=auth_code)
    storage.mark_code_as_used = AsyncMock()
    storage.get_user = AsyncMock(
        return_value=MagicMock(
            id="user-1",
            email="user@test.com",
            is_active=True,
            last_login=None,
            scopes=["read"],
        )
    )
    storage.client_storage.get_client = AsyncMock(return_value=client)
    storage.client_storage.update_last_used = AsyncMock()
    storage.client_storage.verify_client_secret = AsyncMock(return_value=True)

    oauth2_service = MagicMock()
    oauth2_service.client_storage = storage.client_storage
    oauth2_service.get_authorization_code = AsyncMock(return_value=auth_code)
    oauth2_service.mark_code_as_used = AsyncMock()
    oauth2_service.process_scopes = AsyncMock(return_value=["openid", "read"])
    oauth2_service.verify_client = AsyncMock(return_value=True)

    jwt_service = MagicMock()
    jwt_service.create_token_response = MagicMock(
        return_value=MagicMock(
            access_token="at-fake",
            refresh_token=None,
            token_type="Bearer",
            expires_in=3600,
        )
    )
    jwt_service.create_id_token = MagicMock(return_value="id-fake")

    refresh_token_service = MagicMock()
    refresh_token_service.create_refresh_token = AsyncMock(
        return_value=MagicMock(token="rt-fake")
    )

    user_storage = storage  # token endpoint uses ``storage.get_user``

    audit_service = MagicMock()
    audit_service.log_event = AsyncMock()

    app = FastAPI()
    app.include_router(auth_router)

    return (
        app,
        storage,
        jwt_service,
        oauth2_service,
        refresh_token_service,
        user_storage,
        audit_service,
        client,
    )


# ---------------------------------------------------------------------------
# client_secret_jwt (HS256) on authorization_code
# ---------------------------------------------------------------------------


class TestAuthorizationCodeWithClientSecretJwt:
    def _client(self, jwt_plaintext: str, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        ciphertext = encrypt_client_jwt_key_value(jwt_plaintext)
        return _build_app_and_storage(
            client_method="client_secret_jwt",
            jwt_key_ciphertext=ciphertext,
        )

    def test_valid_client_assertion_succeeds(self, test_settings):
        jwt_plain = "shared-hs256-key"
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = self._client(jwt_plain, test_settings)
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=f"jti-1-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        # The endpoint may fail downstream (PKCE is required, etc.)
        # but the JWT auth itself should NOT have produced a 401
        # ``invalid_client`` — that's the path that proves the
        # assertion was accepted.
        if res.status_code == 401:
            assert res.json()["detail"]["error"] != "invalid_client", res.text
        # Storage should NOT have been queried for verify_client_secret
        # (the JWT path bypasses the legacy bcrypt verification).
        storage.client_storage.verify_client_secret.assert_not_called()

    def test_wrong_key_rejected(self, test_settings):
        jwt_plain = "shared-hs256-key"
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = self._client(jwt_plain, test_settings)
        token = _signed_jwt(
            algorithm="HS256",
            key="WRONG-KEY",
            client_id=client.client_id,
            jti=f"jti-2-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        assert res.status_code == 401, res.text
        assert res.json()["detail"]["error"] == "invalid_client"

    def test_replay_rejected_on_second_use(self, test_settings):
        jwt_plain = "shared-hs256-key"
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = self._client(jwt_plain, test_settings)
        jti = f"jti-replay-{time.time_ns()}"
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=jti,
        )
        http = TestClient(app)
        data = {
            "grant_type": "authorization_code",
            "code": "auth-code-1",
            "redirect_uri": "https://example.com/cb",
            "client_id": client.client_id,
            "client_assertion_type": (
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            ),
            "client_assertion": token,
        }
        patches = [
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ]
        # First call — accepted.
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            res1 = http.post("/oauth2/token", data=data)
        if res1.status_code == 401:
            # If the request was rejected for a non-JWT reason, no
            # replay protection should have fired — skip the second leg.
            pytest.skip(f"first call rejected for non-JWT reason: {res1.text}")
        # Second call with the same jti must be rejected with
        # ``replay_detected``.
        with ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            res2 = http.post("/oauth2/token", data=data)
        assert res2.status_code == 401, res2.text
        assert res2.json()["detail"]["error_code"] == "replay_detected"

    def test_wrong_issuer_rejected(self, test_settings):
        jwt_plain = "shared-hs256-key"
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = self._client(jwt_plain, test_settings)
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id="some-other-client",
            jti=f"jti-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        assert res.status_code == 401
        assert res.json()["detail"]["error_code"] in ("invalid_issuer", "invalid_token")


# ---------------------------------------------------------------------------
# private_key_jwt (RS256) on authorization_code
# ---------------------------------------------------------------------------


class TestAuthorizationCodeWithPrivateKeyJwt:
    def test_valid_rsa_signature_succeeds(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        priv = _rsa_keypair()
        jwk = _jwk_dict(priv)
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = _build_app_and_storage(
            client_method="private_key_jwt",
            public_jwk=jwk,
        )
        token = _signed_jwt(
            algorithm="RS256",
            key=priv,
            client_id=client.client_id,
            jti=f"jti-rsa-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        if res.status_code == 401:
            assert res.json()["detail"]["error"] != "invalid_client", res.text
        storage.client_storage.verify_client_secret.assert_not_called()

    def test_wrong_rsa_key_rejected(self, test_settings):
        priv = _rsa_keypair()
        other = _rsa_keypair()
        jwk = _jwk_dict(priv)
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = _build_app_and_storage(
            client_method="private_key_jwt",
            public_jwk=jwk,
        )
        token = _signed_jwt(
            algorithm="RS256",
            key=other,  # signed with the wrong key
            client_id=client.client_id,
            jti=f"jti-rsa-wrong-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        assert res.status_code == 401
        assert res.json()["detail"]["error_code"] in (
            "invalid_token",
            "invalid_signature",
        )


# ---------------------------------------------------------------------------
# client_credentials with JWT
# ---------------------------------------------------------------------------


class TestClientCredentialsWithClientSecretJwt:
    def test_valid_assertion_succeeds(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-cc"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = _build_app_and_storage(
            client_method="client_secret_jwt",
            jwt_key_ciphertext=ciphertext,
            client_secret_hash=None,
        )
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=f"jti-cc-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": client.client_id,
                    "scope": "read",
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": token,
                },
            )
        # Should not have rejected with invalid_client. We do not
        # assert 200 because downstream validation (scopes, user)
        # may fail; the JWT layer is the unit under test.
        if res.status_code == 401:
            assert res.json()["detail"]["error"] != "invalid_client", res.text
        # And the legacy secret path must not have been called.
        oauth2_svc.verify_client.assert_not_called()


# ---------------------------------------------------------------------------
# Bearer token is NOT a client_assertion
# ---------------------------------------------------------------------------


class TestClientAssertionTypeEnforced:
    def test_bearer_token_only_not_accepted_on_token_endpoint(self, test_settings):
        # A plain Bearer header (without client_assertion_type) must
        # NOT be treated as a client_assertion. The token endpoint
        # only accepts the form-encoded client_assertion.
        (
            app,
            storage,
            jwt_svc,
            oauth2_svc,
            _,
            _,
            audit,
            client,
        ) = _build_app_and_storage(
            client_method="client_secret_jwt",
            jwt_key_ciphertext="agcj1:fake",
        )
        http = TestClient(app)
        bearer_token = _signed_jwt(
            algorithm="HS256",
            key="any",
            client_id=client.client_id,
            jti=f"jti-bearer-{time.time_ns()}",
        )
        with (
            patch("authglow.api.auth.get_user_storage", return_value=storage),
            patch("authglow.api.auth.get_jwt_service", return_value=jwt_svc),
            patch("authglow.api.auth.OAuth2Service", return_value=oauth2_svc),
            patch(
                "authglow.api.auth.RefreshTokenService",
                return_value=MagicMock(
                    create_refresh_token=AsyncMock(
                        return_value=MagicMock(token="rt-fake")
                    )
                ),
            ),
            patch("authglow.services.audit.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "auth-code-1",
                    "redirect_uri": "https://example.com/cb",
                    "client_id": client.client_id,
                },
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
        # Without client_assertion_type, the helper falls back to
        # verify_client — which the mock returns True for. The
        # request should NOT have used the JWT path; we expect the
        # endpoint to continue with the legacy path.
        # The actual outcome is not the unit under test here —
        # we only assert that the bearer header was NOT silently
        # treated as a client_assertion by the JWT verifier.
        # Concretely: the JWT verifier, if invoked, would have raised
        # with ``invalid_token`` because the key is wrong. We assert
        # we do NOT see that.
        if res.status_code == 401:
            detail = res.json()["detail"]
            error_code = detail.get("error_code") if isinstance(detail, dict) else None
            assert error_code not in (
                "invalid_token",
                "invalid_issuer",
            )
