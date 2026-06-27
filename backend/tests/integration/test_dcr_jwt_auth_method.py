"""Integration tests for DCR (RFC 7591) with the new T.2 auth methods.

``token_endpoint_auth_method`` accepts ``client_secret_jwt`` and
``private_key_jwt`` in addition to the legacy methods. The server
generates a symmetric key for ``client_secret_jwt`` and accepts an
embedded ``public_jwk`` for ``private_key_jwt``. Invalid method
values are rejected with HTTP 400.
"""

import json
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


def _build_app_and_storage():
    from authglow.api.oidc import router

    storage = MagicMock()
    storage.generate_client_secret.return_value = "fake-secret"

    created_clients = []

    async def _create(client, plaintext_secret):
        # Mimic storage.create_client by recording the saved model
        # so the assertions below can inspect it.
        created_clients.append(client)
        # Replicate the bcrypt-hashing step so the model is realistic.
        from authglow.services.password import hash_password

        client.client_secret = hash_password(plaintext_secret)
        return client

    storage.create_client = AsyncMock(side_effect=_create)
    storage.get_client = AsyncMock(
        side_effect=lambda cid: next(
            (c for c in created_clients if c.client_id == cid), None
        )
    )
    storage._created = created_clients

    audit = MagicMock()
    audit.log_event = AsyncMock()

    app = FastAPI()
    app.include_router(router)
    return app, storage, audit


class TestDcrAuthMethodValidation:
    """The Pydantic schema rejects unknown ``token_endpoint_auth_method``."""

    def test_invalid_method_rejected(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "client_secret_tea",
                },
            )
        assert res.status_code == 422, res.text
        body = res.json()
        # Pydantic validation error mentions the offending field.
        assert "token_endpoint_auth_method" in str(body)

    def test_default_method_is_client_secret_basic(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={"redirect_uris": ["https://example.com/cb"]},
            )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["token_endpoint_auth_method"] == "client_secret_basic"
        # No JWT key for the default method.
        assert body.get("client_secret_jwt_key") is None


class TestDcrClientSecretJwt:
    """``client_secret_jwt`` mints a symmetric key and returns it once."""

    def test_jwt_key_generated_and_returned(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "client_secret_jwt",
                },
            )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["token_endpoint_auth_method"] == "client_secret_jwt"
        # Plaintext key is present (single-use) and Fernet-prefixed on disk.
        jwt_key = body.get("client_secret_jwt_key")
        assert jwt_key, body
        assert len(jwt_key) > 32
        # The persisted client has the *encrypted* key.
        created = storage._created[0]
        assert created.client_secret_jwt_key.startswith("agcj1:"), created
        # Round-trip via the crypto helper proves the stored value
        # can decrypt with the same SECRET_KEY.
        from authglow.services.client_jwt_auth import (
            decrypt_client_jwt_key_value,
        )

        assert decrypt_client_jwt_key_value(created.client_secret_jwt_key) == jwt_key

    def test_jwt_key_not_returned_for_legacy_method(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "client_secret_post",
                },
            )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body.get("client_secret_jwt_key") is None


class TestDcrPrivateKeyJwt:
    """``private_key_jwt`` accepts an embedded ``public_jwk``."""

    def test_public_jwk_stored(self):
        app, storage, audit = _build_app_and_storage()
        priv = _rsa_keypair()
        jwk = _jwk_dict(priv)
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "public_jwk": jwk,
                },
            )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["token_endpoint_auth_method"] == "private_key_jwt"
        # The public JWK is echoed back so the operator can verify
        # what was stored.
        assert body["public_jwk"] == jwk
        created = storage._created[0]
        assert created.public_jwk == jwk
        # No symmetric key is generated for this method.
        assert body.get("client_secret_jwt_key") is None

    def test_invalid_jwk_shape_rejected(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "public_jwk": {"kty": "oct", "k": "not-a-rsa-key"},
                },
            )
        # Pydantic ValidationError → 422.
        assert res.status_code == 422, res.text
        assert "public_jwk" in str(res.json())

    def test_jwk_dict_required(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "public_jwk": "not-a-dict",
                },
            )
        assert res.status_code == 422
        assert "public_jwk" in str(res.json())


class TestDcrAuthMethodAuditLogging:
    """The auth method chosen at registration is recorded in the audit log."""

    def test_audit_event_records_method(self):
        app, storage, audit = _build_app_and_storage()
        http = TestClient(app)
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage", return_value=storage),
            patch("authglow.api.oidc.AuditService", return_value=audit),
        ):
            res = http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                    "token_endpoint_auth_method": "client_secret_jwt",
                },
            )
        assert res.status_code == 201
        # Inspect the audit call metadata.
        assert audit.log_event.await_count >= 1
        call_kwargs = audit.log_event.await_args.kwargs
        metadata = call_kwargs.get("metadata") or {}
        assert metadata.get("token_endpoint_auth_method") == "client_secret_jwt"
