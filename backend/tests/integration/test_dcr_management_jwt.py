"""Integration tests for RFC 7592 DCR Management with JWT-Bearer auth.

``GET`` / ``PUT`` / ``DELETE /oauth2/register/{client_id}`` can be
authenticated either via HTTP Basic (legacy) or ``Authorization: Bearer
<jwt>`` for clients using ``client_secret_jwt`` /
``private_key_jwt`` (T.2).
"""

import base64
import json
import time
from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _rsa_keypair():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _jwk_dict(private_key) -> dict:
    return json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))


def _aud() -> str:
    from authglow.core.config import get_settings

    issuer = get_settings().issuer.rstrip("/")
    return f"{issuer}/oauth2/token"


def _signed_jwt(*, algorithm: str, key, client_id: str, jti: str) -> str:
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": _aud(),
        "exp": now + 60,
        "jti": jti,
    }
    return jwt.encode(payload, key, algorithm=algorithm)


def _build_app_and_client(
    *,
    method: str = "client_secret_jwt",
    jwt_key_ciphertext: str = None,
    public_jwk: dict = None,
    client_id: str = "dcr-mgmt-client",
):
    from authglow.api.oidc import router
    from authglow.models.oauth_client import OAuth2Client
    from authglow.services.password import hash_password

    client = OAuth2Client(
        client_id=client_id,
        client_secret=hash_password("my-plaintext-secret"),
        client_name="DCR Mgmt Test",
        redirect_uris=["https://example.com/cb"],
        grant_types=["authorization_code"],
        allowed_scopes=["read"],
        is_active=True,
        token_endpoint_auth_method=method,
        client_secret_jwt_key=jwt_key_ciphertext,
        public_jwk=public_jwk,
    )

    storage = MagicMock()
    storage.get_client = AsyncMock(return_value=client)
    storage.update_client = AsyncMock()
    storage.delete_client = AsyncMock(return_value=True)

    audit = MagicMock()
    audit.log_event = AsyncMock()

    app = FastAPI()
    app.include_router(router)
    return app, storage, audit, client


class TestDcrManagementBearer:
    """Bearer JWT auth path on GET / PUT / DELETE."""

    def test_get_with_bearer_jwt_succeeds(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-dcr"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_jwt", jwt_key_ciphertext=ciphertext
        )
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=f"jti-get-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["client_id"] == client.client_id
        # T.2 fields are present.
        assert body["token_endpoint_auth_method"] == "client_secret_jwt"
        assert body["has_client_secret_jwt_key"] is True
        # The encrypted JWT key is never returned.
        assert "client_secret_jwt_key" not in body

    def test_put_with_bearer_jwt_succeeds(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-dcr-put"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_jwt", jwt_key_ciphertext=ciphertext
        )
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=f"jti-put-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.put(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"client_name": "Updated Name"},
            )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["client_name"] == "Updated Name"
        storage.update_client.assert_awaited_once()

    def test_delete_with_bearer_jwt_succeeds(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-dcr-del"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_jwt", jwt_key_ciphertext=ciphertext
        )
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id=client.client_id,
            jti=f"jti-del-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.delete(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 204, res.text
        storage.delete_client.assert_awaited_once_with(client.client_id)

    def test_get_with_rsa_bearer_jwt_succeeds(self, test_settings):
        priv = _rsa_keypair()
        app, storage, audit, client = _build_app_and_client(
            method="private_key_jwt",
            public_jwk=_jwk_dict(priv),
        )
        token = _signed_jwt(
            algorithm="RS256",
            key=priv,
            client_id=client.client_id,
            jti=f"jti-rsa-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["token_endpoint_auth_method"] == "private_key_jwt"
        # The public JWK is exposed for read-back; the encrypted
        # JWT key is not relevant here.
        assert body["public_jwk"] is not None

    def test_bearer_jwt_with_wrong_key_rejected(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-dcr"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_jwt", jwt_key_ciphertext=ciphertext
        )
        # Sign with the wrong key.
        token = _signed_jwt(
            algorithm="HS256",
            key="WRONG-KEY",
            client_id=client.client_id,
            jti=f"jti-wrong-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        assert res.status_code == 401, res.text
        assert res.json()["detail"]["error_code"] in (
            "invalid_token",
            "missing_key",
        )

    def test_bearer_jwt_with_mismatched_client_rejected(self, test_settings):
        from authglow.services.client_jwt_auth import encrypt_client_jwt_key_value

        jwt_plain = "shared-hs256-key-dcr"
        ciphertext = encrypt_client_jwt_key_value(jwt_plain)
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_jwt", jwt_key_ciphertext=ciphertext
        )
        # Sign with a client_id that does not match the URL.
        token = _signed_jwt(
            algorithm="HS256",
            key=jwt_plain,
            client_id="some-other-client",
            jti=f"jti-mismatch-{time.time_ns()}",
        )
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
        # Mismatch is caught by the pre-verification client-id
        # check in ``_authenticate_client_for_dcr`` — the
        # response detail is a plain string (pre-verify, not
        # post-verify) so we just assert the 401.
        assert res.status_code == 401, res.text

    def test_no_auth_rejected(self):
        app, storage, audit, client = _build_app_and_client()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(f"/oauth2/register/{client.client_id}")
        assert res.status_code == 401
        # ``WWW-Authenticate`` advertises both Basic and Bearer.
        www = res.headers.get("www-authenticate", "")
        assert "Basic" in www
        assert "Bearer" in www


class TestDcrManagementBasicStillWorks:
    """HTTP Basic continues to work alongside the new Bearer path."""

    def test_get_with_basic_succeeds(self, test_settings):
        from authglow.services.password import hash_password

        plaintext = "my-plaintext-secret"
        app, storage, audit, client = _build_app_and_client(
            method="client_secret_basic",
            client_id="basic-mgmt",
        )
        # Override the hash with the actual plaintext so the
        # ``verify_password_async`` mock returns True.
        client.client_secret = hash_password(plaintext)
        http = TestClient(app)
        creds = base64.b64encode(
            f"{client.client_id}:{plaintext}".encode()
        ).decode()
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.get(
                f"/oauth2/register/{client.client_id}",
                headers={"Authorization": f"Basic {creds}"},
            )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["client_id"] == client.client_id
