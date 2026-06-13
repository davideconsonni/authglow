"""Unit tests for the federation state token (stateless OIDC CSRF protection)."""

import time
from unittest.mock import patch

import jwt as pyjwt
import pytest

from authglow.core.crypto import derive_federation_state_key
from authglow.services.federation_state import (
    EXPIRY_SECONDS,
    FederationStateError,
    FederationStateToken,
)


@pytest.fixture
def state_token(test_settings):
    with patch("authglow.services.federation_state.get_settings", return_value=test_settings):
        return FederationStateToken()


class TestSign:
    def test_sign_returns_jwt_and_nonce(self, state_token):
        signed = state_token.sign("google", "https://app.example.com/cb")
        assert "state" in signed
        assert "nonce" in signed
        assert len(signed["nonce"]) >= 32
        # A HS256 JWT has 3 dot-separated base64url segments
        assert signed["state"].count(".") == 2

    def test_sign_uses_passed_nonce(self, state_token):
        signed = state_token.sign("google", "https://app.example.com/cb", nonce="fixed-nonce")
        assert signed["nonce"] == "fixed-nonce"

    def test_sign_embeds_required_claims(self, state_token):
        signed = state_token.sign("google", "https://app.example.com/cb")
        claims = pyjwt.decode(signed["state"], options={"verify_signature": False})
        for claim in (
            "iss",
            "aud",
            "sub",
            "provider_id",
            "redirect_uri",
            "nonce",
            "jti",
            "iat",
            "exp",
        ):
            assert claim in claims, f"missing claim: {claim}"
        assert claims["provider_id"] == "google"
        assert claims["redirect_uri"] == "https://app.example.com/cb"
        assert claims["aud"] == "federation"


class TestVerify:
    def test_verify_roundtrip(self, state_token):
        signed = state_token.sign("google", "https://app.example.com/cb")
        claims = state_token.verify(signed["state"])
        assert claims["provider_id"] == "google"
        assert claims["redirect_uri"] == "https://app.example.com/cb"
        assert claims["nonce"] == signed["nonce"]

    def test_verify_rejects_missing_token(self, state_token):
        with pytest.raises(FederationStateError, match="missing"):
            state_token.verify("")

    def test_verify_rejects_garbage(self, state_token):
        with pytest.raises(FederationStateError):
            state_token.verify("not-a-jwt")

    def test_verify_rejects_tampered_signature(self, state_token, test_settings):
        signed = state_token.sign("google", "https://app.example.com/cb")
        # Flip a byte in the signature segment
        head, _payload, sig = signed["state"].split(".")
        tampered = f"{head}.{_payload}.{sig[:-4]}AAAA"
        with pytest.raises(FederationStateError):
            state_token.verify(tampered)

    def test_verify_rejects_signed_with_wrong_key(self, state_token):
        signed = state_token.sign("google", "https://app.example.com/cb")
        # Re-sign with a different secret
        claims = pyjwt.decode(signed["state"], options={"verify_signature": False})
        forged = pyjwt.encode(claims, "another-secret-of-at-least-32-chars!", algorithm="HS256")
        with pytest.raises(FederationStateError):
            state_token.verify(forged)

    def test_verify_rejects_expired(self, state_token, test_settings):
        with patch("authglow.services.federation_state.get_settings", return_value=test_settings):
            # Manually mint an expired token
            now = int(time.time()) - (EXPIRY_SECONDS + 60)
            claims = {
                "iss": "authglow",
                "aud": "federation",
                "sub": "google",
                "provider_id": "google",
                "redirect_uri": "https://app.example.com/cb",
                "nonce": "n",
                "jti": "deadbeef",
                "iat": now,
                "exp": now + EXPIRY_SECONDS,
            }
            token = pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")
            with pytest.raises(FederationStateError, match="expired"):
                state_token.verify(token)

    def test_verify_rejects_wrong_audience(self, state_token, test_settings):
        now = int(time.time())
        claims = {
            "iss": "authglow",
            "aud": "some-other-purpose",
            "sub": "google",
            "provider_id": "google",
            "redirect_uri": "https://app.example.com/cb",
            "nonce": "n",
            "jti": "deadbeef",
            "iat": now,
            "exp": now + EXPIRY_SECONDS,
        }
        token = pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")
        with pytest.raises(FederationStateError, match="audience"):
            state_token.verify(token)

    def test_verify_rejects_wrong_issuer(self, state_token, test_settings):
        now = int(time.time())
        claims = {
            "iss": "evil-idp",
            "aud": "federation",
            "sub": "google",
            "provider_id": "google",
            "redirect_uri": "https://app.example.com/cb",
            "nonce": "n",
            "jti": "deadbeef",
            "iat": now,
            "exp": now + EXPIRY_SECONDS,
        }
        token = pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")
        with pytest.raises(FederationStateError, match="issuer"):
            state_token.verify(token)

    def test_verify_rejects_missing_required_claim(self, state_token, test_settings):
        now = int(time.time())
        # Missing 'nonce'
        claims = {
            "iss": "authglow",
            "aud": "federation",
            "sub": "google",
            "provider_id": "google",
            "redirect_uri": "https://app.example.com/cb",
            "jti": "deadbeef",
            "iat": now,
            "exp": now + EXPIRY_SECONDS,
        }
        token = pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")
        with pytest.raises(FederationStateError, match="nonce"):
            state_token.verify(token)


class TestOAuth2Context:
    def test_sign_embeds_oauth2_context(self, state_token, test_settings):
        oauth2_ctx = {
            "client_id": "my-client",
            "oauth_redirect_uri": "https://app.example.com/cb",
            "scope": "openid email",
            "app_state": "xyz",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "response_type": "code",
            "oidc_nonce": "n123",
        }
        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )
        claims = pyjwt.decode(signed["state"], options={"verify_signature": False})
        assert "oauth2_context" in claims
        assert claims["oauth2_context"] == oauth2_ctx

    def test_sign_without_oauth2_context_omits_field(self, state_token):
        signed = state_token.sign("google", "https://idp.example.com/cb")
        claims = pyjwt.decode(signed["state"], options={"verify_signature": False})
        assert "oauth2_context" not in claims

    def test_verify_roundtrip_with_oauth2_context(self, state_token):
        oauth2_ctx = {
            "client_id": "my-client",
            "oauth_redirect_uri": "https://app.example.com/cb",
            "scope": "openid profile",
            "app_state": "app-state-123",
            "code_challenge": "",
            "code_challenge_method": "",
            "response_type": "code",
            "oidc_nonce": "",
        }
        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )
        claims = state_token.verify(signed["state"])
        assert claims["provider_id"] == "google"
        assert claims["oauth2_context"] == oauth2_ctx

    def test_get_oauth2_context_returns_none_when_missing(self, state_token):
        signed = state_token.sign("google", "https://idp.example.com/cb")
        claims = state_token.verify(signed["state"])
        assert FederationStateToken.get_oauth2_context(claims) is None

    def test_get_oauth2_context_returns_none_when_no_client_id(self, state_token):
        oauth2_ctx = {
            "client_id": "",
            "oauth_redirect_uri": "https://app.example.com/cb",
        }
        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )
        claims = state_token.verify(signed["state"])
        assert FederationStateToken.get_oauth2_context(claims) is None

    def test_get_oauth2_context_returns_none_when_no_redirect_uri(self, state_token):
        oauth2_ctx = {
            "client_id": "my-client",
            "oauth_redirect_uri": "",
        }
        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )
        claims = state_token.verify(signed["state"])
        assert FederationStateToken.get_oauth2_context(claims) is None

    def test_get_oauth2_context_returns_context_when_valid(self, state_token):
        oauth2_ctx = {
            "client_id": "my-client",
            "oauth_redirect_uri": "https://app.example.com/cb",
            "scope": "openid",
            "app_state": "xyz",
            "code_challenge": "",
            "code_challenge_method": "",
            "response_type": "code",
            "oidc_nonce": "",
        }
        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )
        claims = state_token.verify(signed["state"])
        result = FederationStateToken.get_oauth2_context(claims)
        assert result is not None
        assert result["client_id"] == "my-client"
        assert result["oauth_redirect_uri"] == "https://app.example.com/cb"
