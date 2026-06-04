"""Unit tests for FederationService.verify_id_token algorithm validation (VAPT-015).

Validates that the ``alg`` claim in the unverified JWT header is checked against
a static allowlist before the token is decoded, preventing alg-confusion attacks
where a compromised IdP changes ``alg`` from RS256 to HS256 to trick the verifier
into using the RSA public key as HMAC material.
"""

import base64
import json as _json
import secrets
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, patch

import jwt as pyjwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from authglow.models.federation import ExternalIdpConfig
from authglow.services.federation import (
    _ALLOWED_FEDERATION_ALGORITHMS,
    FederationService,
    JWKSVerificationError,
)


def _generate_rsa_key_pair():
    """Generate a real 2048-bit RSA key pair for testing."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())


def _public_key_to_jwk(public_key, kid: str = "test-key-1") -> Dict[str, str]:
    """Convert an RSA public key to a JWK dict (RFC 7517)."""
    numbers = public_key.public_numbers()
    n_len = (numbers.n.bit_length() + 7) // 8
    e_len = (numbers.e.bit_length() + 7) // 8
    return {
        "kty": "RSA",
        "kid": kid,
        "n": base64.urlsafe_b64encode(numbers.n.to_bytes(n_len, "big"))
        .rstrip(b"=")
        .decode("ascii"),
        "e": base64.urlsafe_b64encode(numbers.e.to_bytes(e_len, "big"))
        .rstrip(b"=")
        .decode("ascii"),
        "alg": "RS256",
        "use": "sig",
    }


def _make_jwks_client(jwk_dict: Dict[str, str]) -> pyjwt.PyJWKClient:
    """Create a PyJWKClient pre-loaded with the given JWK, no HTTP fetch needed."""
    jwk_data: Dict[str, Any] = {"keys": [jwk_dict]}
    client = pyjwt.PyJWKClient("https://test.invalid", cache_keys=True, lifespan=3600)
    client.fetch_data = lambda: jwk_data
    return client


def _base_id_token_claims(
    *, iss: str = "https://idp.example.com", aud: str = "test-client", nonce: str = ""
) -> Dict[str, Any]:
    """Return a minimal valid set of OIDC claims for test id_tokens."""
    now = int(time.time())
    claims: Dict[str, Any] = {
        "iss": iss,
        "sub": "user-123",
        "aud": aud,
        "iat": now,
        "exp": now + 600,
    }
    if nonce:
        claims["nonce"] = nonce
    return claims


def _make_provider(
    provider_id: str = "test-provider",
    issuer: str = "https://idp.example.com",
    client_id: str = "test-client",
) -> ExternalIdpConfig:
    """Create a real ExternalIdpConfig for testing."""
    return ExternalIdpConfig(
        id=provider_id,
        label="Test IdP",
        description="Test identity provider",
        issuer=issuer,
        client_id=client_id,
        client_secret="test-secret-32-chars-long-!!",
        scopes=["openid", "email", "profile"],
        claims_mapping={"sub": "external_id", "email": "email", "name": "name"},
        enabled=True,
    )


class TestVerifyIdTokenAlgorithmValidation:
    """VAPT-015: alg in the unverified header must be validated against a static allowlist."""

    async def test_accepts_rs256_token(self):
        """A properly signed RS256 id_token is verified successfully."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        claims = _base_id_token_claims()
        id_token = pyjwt.encode(
            claims, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
        )

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            result = await service.verify_id_token(provider, id_token)

        assert result["sub"] == "user-123"
        assert result["iss"] == "https://idp.example.com"

    async def test_accepts_rs256_token_with_nonce(self):
        """RS256 token with matching nonce is verified."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        claims = _base_id_token_claims(nonce="nonce-12345")
        id_token = pyjwt.encode(
            claims, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
        )

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            result = await service.verify_id_token(provider, id_token, nonce="nonce-12345")

        assert result["nonce"] == "nonce-12345"

    async def test_rejects_nonce_mismatch(self):
        """RS256 token with non-matching nonce is rejected."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        claims = _base_id_token_claims(nonce="good-nonce")
        id_token = pyjwt.encode(
            claims, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
        )

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            with pytest.raises(JWKSVerificationError, match="nonce mismatch"):
                await service.verify_id_token(provider, id_token, nonce="wrong-nonce")

    async def test_rejects_hs256_alg_in_header(self):
        """Token with alg=HS256 in the header is rejected BEFORE decode (VAPT-015 fix)."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        claims = _base_id_token_claims()
        hmac_secret = secrets.token_bytes(32)
        # Sign with HS256 but include a kid so the JWKS lookup succeeds
        id_token = pyjwt.encode(
            claims, hmac_secret, algorithm="HS256", headers={"kid": "test-key-1"}
        )

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            with pytest.raises(JWKSVerificationError) as exc_info:
                await service.verify_id_token(provider, id_token)

        error_msg = str(exc_info.value)
        assert "alg" in error_msg.lower()
        assert "HS256" in error_msg

    async def test_rejects_unknown_alg_in_header(self):
        """Token with an unknown alg in the header is rejected."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        claims = _base_id_token_claims()
        # Sign with RS256 but override the alg header to "none"
        id_token = pyjwt.encode(
            claims, private_key, algorithm="RS256", headers={"kid": "test-key-1"}
        )
        # Manually rewrite the header alg
        header_b64, payload_b64, sig = id_token.split(".")
        header = _json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        header["alg"] = "none"
        tampered_header = (
            base64.urlsafe_b64encode(_json.dumps(header).encode()).rstrip(b"=").decode("ascii")
        )
        tampered_token = f"{tampered_header}.{payload_b64}.{sig}"

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            with pytest.raises(JWKSVerificationError) as exc_info:
                await service.verify_id_token(provider, tampered_token)

        error_msg = str(exc_info.value)
        assert "alg" in error_msg.lower()
        assert "none" in error_msg.lower()

    def test_allowed_algorithms_constant(self):
        """The allowlist only contains asymmetric algorithms, not HS256."""
        assert "RS256" in _ALLOWED_FEDERATION_ALGORITHMS
        assert "HS256" not in _ALLOWED_FEDERATION_ALGORITHMS
        assert "HS384" not in _ALLOWED_FEDERATION_ALGORITHMS
        assert "HS512" not in _ALLOWED_FEDERATION_ALGORITHMS
        assert "none" not in _ALLOWED_FEDERATION_ALGORITHMS

    async def test_rejects_token_signed_with_different_key(self):
        """Token signed with a different RSA key is rejected by signature verification."""
        private_key = _generate_rsa_key_pair()
        public_jwk = _public_key_to_jwk(private_key.public_key())
        jwks_client = _make_jwks_client(public_jwk)

        other_key = _generate_rsa_key_pair()
        claims = _base_id_token_claims()
        id_token = pyjwt.encode(claims, other_key, algorithm="RS256", headers={"kid": "test-key-1"})

        service = FederationService()
        provider = _make_provider()

        with patch.object(
            service,
            "_get_jwks_client_async",
            AsyncMock(return_value=jwks_client),
        ):
            with pytest.raises(JWKSVerificationError):
                await service.verify_id_token(provider, id_token)
