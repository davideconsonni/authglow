"""Standard OAuth2/OIDC conformance clients (OA-002).

Five reusable, function-scoped fixtures with fixed, documented values for the
conformance matrix (OA-001):

- ``conf_public_pkce_client`` — public client, ``token_endpoint_auth_method="none"``,
  ``require_pkce=True``. Redirect: ``https://example.com/cb``.
- ``conf_confidential_basic_client`` — confidential client,
  ``token_endpoint_auth_method="client_secret_basic"``.
  Redirect: ``https://example.com/cb``.
- ``conf_private_key_jwt_client`` — confidential client,
  ``token_endpoint_auth_method="private_key_jwt"`` with an embedded ``public_jwk``
  derived from the session-scoped ``test_keys_dir`` RSA key (never generated
  per-fixture, never a real secret).
- ``conf_dpop_bound_client`` — confidential Basic client with ``dpop_bound=True``.
- ``conf_device_client`` — public client with the RFC 8628 device grant
  (``urn:ietf:params:oauth:grant-type:device_code`` + ``refresh_token``),
  no ``redirect_uris`` (no ``authorization_code`` grant), ``require_pkce=False``.

Isolation rules (per AGENTS.md): every fixture depends on ``test_settings``
(``tmp_path``-backed, ``bcrypt_rounds=4``), passes ``settings=`` explicitly to
the repository and service constructors (``lru_cache`` bypass), creates the
client through the REAL ``OAuth2ClientStorage`` + ``FileOAuth2ClientRepository``
(no mocks), and deletes it on teardown. Plaintext secrets are generated at
runtime via ``secrets.token_urlsafe()``.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from typing import TYPE_CHECKING, Any, Dict, Iterator, Optional

import pytest

if TYPE_CHECKING:
    from authglow.core.config import Settings
    from authglow.models.oauth_client import OAuth2Client

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

_CONFORMANCE_REDIRECT_URI = "https://example.com/cb"
_CONFORMANCE_SCOPES = ["openid", "profile", "email", "offline_access", "read"]


def _create_client(test_settings: Settings, plaintext_secret: str, **fields: Any) -> OAuth2Client:
    """Persist a client via the real service + file repository."""
    from unittest.mock import patch

    from authglow.core.cache import _reset_cache_registry
    from authglow.models.oauth_client import OAuth2Client
    from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
    from authglow.services.oauth_client import OAuth2ClientStorage

    _reset_cache_registry()
    repo = FileOAuth2ClientRepository(settings=test_settings)
    storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
    client = OAuth2Client(client_secret="placeholder", **fields)
    with patch("authglow.services.password.get_settings", return_value=test_settings):
        return asyncio.run(storage.create_client(client, plaintext_secret))


def _delete_client(test_settings: Settings, client_id: str) -> None:
    """Remove a client created by :func:`_create_client` (teardown)."""
    from authglow.repositories.file.oauth_client import FileOAuth2ClientRepository
    from authglow.services.oauth_client import OAuth2ClientStorage

    repo = FileOAuth2ClientRepository(settings=test_settings)
    storage = OAuth2ClientStorage(repository=repo, settings=test_settings)
    asyncio.run(storage.delete_client(client_id))


def _load_public_jwk(test_keys_dir: str) -> Dict[str, Any]:
    """Return the session test RSA public key as a JWK dict."""
    import jwt
    from cryptography.hazmat.primitives import serialization

    with open(f"{test_keys_dir}/public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))


def _bundle(
    client: OAuth2Client, secret: Optional[str], public_jwk: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Standard fixture payload: client + wire credentials for OA-001 tests."""
    return {"client": client, "secret": secret, "public_jwk": public_jwk}


@pytest.fixture
def conf_public_pkce_client(test_settings) -> Iterator[Dict[str, Any]]:
    """Public PKCE client (``token_endpoint_auth_method="none"``)."""
    secret = secrets.token_urlsafe(32)
    client = _create_client(
        test_settings,
        secret,
        client_name="Conformance Public PKCE",
        redirect_uris=[_CONFORMANCE_REDIRECT_URI],
        allowed_scopes=_CONFORMANCE_SCOPES,
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=False,
        require_pkce=True,
        token_endpoint_auth_method="none",
    )
    yield _bundle(client, secret)
    _delete_client(test_settings, client.client_id)


@pytest.fixture
def conf_confidential_basic_client(test_settings) -> Iterator[Dict[str, Any]]:
    """Confidential Basic client (``token_endpoint_auth_method="client_secret_basic"``)."""
    secret = secrets.token_urlsafe(32)
    client = _create_client(
        test_settings,
        secret,
        client_name="Conformance Confidential Basic",
        redirect_uris=[_CONFORMANCE_REDIRECT_URI],
        allowed_scopes=_CONFORMANCE_SCOPES,
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        token_endpoint_auth_method="client_secret_basic",
    )
    yield _bundle(client, secret)
    _delete_client(test_settings, client.client_id)


@pytest.fixture
def conf_private_key_jwt_client(test_settings, test_keys_dir) -> Iterator[Dict[str, Any]]:
    """``private_key_jwt`` client with the session test key as embedded ``public_jwk``."""
    public_jwk = _load_public_jwk(test_keys_dir)
    secret = secrets.token_urlsafe(32)
    client = _create_client(
        test_settings,
        secret,
        client_name="Conformance Private Key JWT",
        redirect_uris=[_CONFORMANCE_REDIRECT_URI],
        allowed_scopes=_CONFORMANCE_SCOPES,
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        token_endpoint_auth_method="private_key_jwt",
        public_jwk=public_jwk,
    )
    yield _bundle(client, secret, public_jwk)
    _delete_client(test_settings, client.client_id)


@pytest.fixture
def conf_dpop_bound_client(test_settings) -> Iterator[Dict[str, Any]]:
    """DPoP-bound confidential client (``dpop_bound=True``)."""
    secret = secrets.token_urlsafe(32)
    client = _create_client(
        test_settings,
        secret,
        client_name="Conformance DPoP Bound",
        redirect_uris=[_CONFORMANCE_REDIRECT_URI],
        allowed_scopes=_CONFORMANCE_SCOPES,
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=True,
        require_pkce=True,
        token_endpoint_auth_method="client_secret_basic",
        dpop_bound=True,
    )
    yield _bundle(client, secret)
    _delete_client(test_settings, client.client_id)


@pytest.fixture
def conf_device_client(test_settings) -> Iterator[Dict[str, Any]]:
    """Public device-flow client (RFC 8628 device grant, no ``authorization_code``)."""
    secret = secrets.token_urlsafe(32)
    client = _create_client(
        test_settings,
        secret,
        client_name="Conformance Device Client",
        redirect_uris=[],
        allowed_scopes=["read"],
        grant_types=[DEVICE_GRANT, "refresh_token"],
        is_confidential=False,
        require_pkce=False,
        token_endpoint_auth_method="none",
    )
    yield _bundle(client, secret)
    _delete_client(test_settings, client.client_id)
