"""Unit tests for :mod:`authglow.services.client_jwt_auth`.

CONFORMANCE_REMEDIATION_PLAN.md T.2: ``client_secret_jwt`` (HS256)
and ``private_key_jwt`` (RS256) client authentication at the OAuth 2.0
token endpoint.

The tests in this file exercise the cryptographic core in isolation
— they do not touch the FastAPI app. Integration coverage of the
token endpoint / DCR endpoints is in
``tests/integration/test_token_endpoint_jwt_auth.py``,
``test_dcr_jwt_auth_method.py`` and ``test_dcr_management_jwt.py``.
"""

import json
import time
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException, Request

from authglow.models.oauth_client import OAuth2Client
from authglow.services.client_jwt_auth import (
    CLIENT_ASSERTION_TYPE_JWT_BEARER,
    assert_jwt_claims,
    decrypt_client_jwt_key_value,
    encrypt_client_jwt_key_value,
    generate_client_jwt_symmetric_key,
    replay_protect_jti,
    verify_client_assertion,
    verify_client_secret_jwt,
    verify_private_key_jwt,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _generate_rsa_key_pair():
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _public_jwk_for(private_key) -> dict:
    """Return the RSA public key as a JWK dict.

    ``jwt.algorithms.RSAAlgorithm.to_jwk`` returns a JSON-encoded
    string; we parse it so the model's ``public_jwk: dict`` field
    accepts the value.
    """
    public_key = private_key.public_key()
    jwk_str = jwt.algorithms.RSAAlgorithm.to_jwk(public_key)
    return json.loads(jwk_str)


def _make_client(
    *,
    method: str = "client_secret_basic",
    jwt_key_ciphertext: str = None,
    public_jwk: dict = None,
    client_id: str = "cid-test",
) -> OAuth2Client:
    return OAuth2Client(
        client_id=client_id,
        client_secret="x" * 60,  # bcrypt-shaped placeholder
        client_name="Test Client",
        redirect_uris=["https://example.com/cb"],
        grant_types=["authorization_code"],
        is_confidential=True,
        token_endpoint_auth_method=method,
        client_secret_jwt_key=jwt_key_ciphertext,
        public_jwk=public_jwk,
    )


def _make_request(audience_base: str = "http://localhost:8000") -> Request:
    req = MagicMock(spec=Request)
    # The client_jwt_auth helper calls ``request.url`` only via the
    # ``get_settings().issuer`` indirection; we patch the audience
    # through ``Settings.issuer`` instead of inspecting the request.
    return req


def _aud_for_settings(test_settings) -> str:
    """Build a token-endpoint audience URL matching ``test_settings.issuer``.

    T.2 / RFC 7523 §3: the ``aud`` claim must match the token
    endpoint. We derive it from the patched settings so the test
    follows whatever the dev ``.env`` configured (typically
    ``http://localhost:8001``).
    """
    from authglow.core.config import get_settings

    issuer = get_settings().issuer.rstrip("/")
    return f"{issuer}/oauth2/token"


# ---------------------------------------------------------------------------
# Encryption round-trip
# ---------------------------------------------------------------------------


class TestClientJwtKeyEncryption:
    """``encrypt_client_jwt_key_value`` / ``decrypt_client_jwt_key_value``."""

    def test_roundtrip_preserves_plaintext(self):
        plaintext = generate_client_jwt_symmetric_key()
        ciphertext = encrypt_client_jwt_key_value(plaintext)
        assert ciphertext.startswith("agcj1:")
        assert decrypt_client_jwt_key_value(ciphertext) == plaintext

    def test_empty_value_passes_through(self):
        assert encrypt_client_jwt_key_value("") == ""
        assert decrypt_client_jwt_key_value("") == ""
        assert decrypt_client_jwt_key_value(None) == ""

    def test_malformed_ciphertext_raises(self):
        with pytest.raises(ValueError):
            decrypt_client_jwt_key_value("not-a-real-ciphertext")

    def test_different_plaintexts_yield_different_ciphertexts(self):
        # AES-GCM is randomised — same plaintext must not produce
        # the same ciphertext twice.
        plaintext = generate_client_jwt_symmetric_key()
        a = encrypt_client_jwt_key_value(plaintext)
        b = encrypt_client_jwt_key_value(plaintext)
        assert a != b
        assert decrypt_client_jwt_key_value(a) == plaintext
        assert decrypt_client_jwt_key_value(b) == plaintext


# ---------------------------------------------------------------------------
# JTI replay protection
# ---------------------------------------------------------------------------


class TestReplayProtection:
    def test_first_seen_jti_proceeds(self):
        jti = f"jti-{time.time_ns()}"
        assert replay_protect_jti(jti, int(time.time()) + 60) is True

    def test_duplicate_jti_is_rejected(self):
        jti = f"jti-{time.time_ns()}"
        assert replay_protect_jti(jti, int(time.time()) + 60) is True
        assert replay_protect_jti(jti, int(time.time()) + 60) is False

    def test_empty_jti_passes_through(self):
        # Claim check is responsible for rejecting empty jti; the
        # replay-protect helper is a no-op in that case.
        assert replay_protect_jti("", int(time.time()) + 60) is True


# ---------------------------------------------------------------------------
# HS256 / client_secret_jwt
# ---------------------------------------------------------------------------


class TestClientSecretJwt:
    def test_valid_signature_returns_claims(self, test_settings):
        key = generate_client_jwt_symmetric_key()
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": "jti-1",
            },
            key,
            algorithm="HS256",
        )
        claims = verify_client_secret_jwt(token, key)
        assert claims["iss"] == "cid-1"
        assert claims["jti"] == "jti-1"

    def test_wrong_key_rejected(self, test_settings):
        key = generate_client_jwt_symmetric_key()
        other = generate_client_jwt_symmetric_key()
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": "jti-1",
            },
            key,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_secret_jwt(token, other)
        assert ei.value.status_code == 401
        assert ei.value.detail["error"] == "invalid_client"

    def test_expired_token_rejected(self, test_settings):
        key = generate_client_jwt_symmetric_key()
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now - 120,
                "jti": "jti-1",
            },
            key,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_secret_jwt(token, key)
        assert ei.value.detail["error_code"] in ("expired", "missing_exp")

    def test_missing_required_claim_rejected(self, test_settings):
        key = generate_client_jwt_symmetric_key()
        now = int(time.time())
        # Missing ``jti``
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
            },
            key,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_secret_jwt(token, key)
        assert ei.value.status_code == 401

    def test_alg_none_rejected(self, test_settings):
        # PyJWT rejects ``alg=none`` by default in encode(); we craft
        # the token manually to confirm the verifier also rejects it.
        import base64
        import json

        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps(
                {
                    "iss": "cid-1",
                    "sub": "cid-1",
                    "aud": _aud_for_settings(test_settings),
                    "exp": int(time.time()) + 60,
                    "jti": "jti-1",
                }
            ).encode()
        ).rstrip(b"=")
        token = f"{header.decode()}.{payload.decode()}."

        with pytest.raises(HTTPException):
            verify_client_secret_jwt(token, "any-key")


# ---------------------------------------------------------------------------
# RS256 / private_key_jwt
# ---------------------------------------------------------------------------


class TestPrivateKeyJwt:
    def test_valid_signature_returns_claims(self, test_settings):
        priv = _generate_rsa_key_pair()
        jwk = _public_jwk_for(priv)
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": "jti-1",
            },
            priv,
            algorithm="RS256",
        )
        claims = verify_private_key_jwt(token, jwk)
        assert claims["jti"] == "jti-1"

    def test_wrong_key_rejected(self, test_settings):
        priv = _generate_rsa_key_pair()
        other = _generate_rsa_key_pair()
        jwk = _public_jwk_for(priv)
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": "jti-1",
            },
            other,  # signed with the wrong key
            algorithm="RS256",
        )
        with pytest.raises(HTTPException) as ei:
            verify_private_key_jwt(token, jwk)
        assert ei.value.status_code == 401

    def test_non_rsa_jwk_rejected(self, test_settings):
        priv = _generate_rsa_key_pair()
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": "cid-1",
                "sub": "cid-1",
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": "jti-1",
            },
            priv,
            algorithm="RS256",
        )
        with pytest.raises(HTTPException):
            verify_private_key_jwt(token, {"kty": "EC", "crv": "P-256", "x": "x", "y": "y"})


# ---------------------------------------------------------------------------
# Claim assertion (RFC 7523 §3)
# ---------------------------------------------------------------------------


class TestClaimAssertion:
    def _claims(self, test_settings, **overrides):
        now = int(time.time())
        base = {
            "iss": "cid-1",
            "sub": "cid-1",
            "aud": _aud_for_settings(test_settings),
            "exp": now + 60,
            "jti": f"jti-{time.time_ns()}",
        }
        base.update(overrides)
        return base

    def test_happy_path_passes(self, test_settings):
        client = _make_client(client_id="cid-1")
        assert_jwt_claims(self._claims(test_settings), client, _make_request())

    def test_wrong_issuer_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(
                self._claims(test_settings, iss="other-cid"), client, _make_request()
            )
        assert ei.value.detail["error_code"] == "invalid_issuer"

    def test_wrong_subject_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(
                self._claims(test_settings, sub="other-cid"), client, _make_request()
            )
        assert ei.value.detail["error_code"] == "invalid_subject"

    def test_missing_subject_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        claims = self._claims(test_settings)
        claims.pop("sub", None)
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(claims, client, _make_request())
        assert ei.value.detail["error_code"] == "missing_subject"

    def test_wrong_audience_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(
                self._claims(test_settings, aud="https://attacker.example/token"),
                client,
                _make_request(),
            )
        assert ei.value.detail["error_code"] == "invalid_audience"

    def test_missing_jti_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        claims = self._claims(test_settings)
        claims.pop("jti", None)
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(claims, client, _make_request())
        assert ei.value.detail["error_code"] == "missing_jti"

    def test_excessive_lifetime_rejected(self, test_settings):
        client = _make_client(client_id="cid-1")
        with pytest.raises(HTTPException) as ei:
            assert_jwt_claims(
                self._claims(test_settings, exp=int(time.time()) + 3600),
                client,
                _make_request(),
            )
        assert ei.value.detail["error_code"] == "excessive_lifetime"


# ---------------------------------------------------------------------------
# Top-level: verify_client_assertion (dispatch on token_endpoint_auth_method)
# ---------------------------------------------------------------------------


class TestVerifyClientAssertion:
    def test_client_secret_jwt_happy_path(self, test_settings):
        priv = generate_client_jwt_symmetric_key()
        ciphertext = encrypt_client_jwt_key_value(priv)
        client = _make_client(
            method="client_secret_jwt",
            jwt_key_ciphertext=ciphertext,
        )
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": client.client_id,
                "sub": client.client_id,
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": f"jti-{time.time_ns()}",
            },
            priv,
            algorithm="HS256",
        )
        # Should NOT raise.
        verify_client_assertion(
            _make_request(),
            client,
            client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
            client_assertion=token,
        )

    def test_private_key_jwt_happy_path(self, test_settings):
        priv = _generate_rsa_key_pair()
        client = _make_client(
            method="private_key_jwt",
            public_jwk=_public_jwk_for(priv),
        )
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": client.client_id,
                "sub": client.client_id,
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": f"jti-{time.time_ns()}",
            },
            priv,
            algorithm="RS256",
        )
        verify_client_assertion(
            _make_request(),
            client,
            client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
            client_assertion=token,
        )

    def test_replay_detected(self, test_settings):
        priv = generate_client_jwt_symmetric_key()
        ciphertext = encrypt_client_jwt_key_value(priv)
        client = _make_client(
            method="client_secret_jwt",
            jwt_key_ciphertext=ciphertext,
        )
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": client.client_id,
                "sub": client.client_id,
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": f"jti-replay-{time.time_ns()}",
            },
            priv,
            algorithm="HS256",
        )
        # First use succeeds.
        verify_client_assertion(
            _make_request(),
            client,
            client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
            client_assertion=token,
        )
        # Second use with same jti is rejected.
        with pytest.raises(HTTPException) as ei:
            verify_client_assertion(
                _make_request(),
                client,
                client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
                client_assertion=token,
            )
        assert ei.value.detail["error_code"] == "replay_detected"

    def test_wrong_assertion_type_rejected(self, test_settings):
        priv = generate_client_jwt_symmetric_key()
        ciphertext = encrypt_client_jwt_key_value(priv)
        client = _make_client(
            method="client_secret_jwt",
            jwt_key_ciphertext=ciphertext,
        )
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": client.client_id,
                "sub": client.client_id,
                "aud": _aud_for_settings(test_settings),
                "exp": now + 60,
                "jti": f"jti-{time.time_ns()}",
            },
            priv,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_assertion(
                _make_request(),
                client,
                client_assertion_type="urn:wrong",
                client_assertion=token,
            )
        assert ei.value.detail["error_code"] == "invalid_assertion_type"

    def test_missing_client_jwt_key_rejected(self, test_settings):
        # Client is registered for ``client_secret_jwt`` but no key
        # was minted at creation. Must be a hard 401, not a crash.
        client = _make_client(
            method="client_secret_jwt",
            jwt_key_ciphertext=None,
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_assertion(
                _make_request(),
                client,
                client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
                client_assertion="any.token.value",
            )
        assert ei.value.detail["error_code"] == "missing_key"

    def test_missing_public_jwk_rejected(self, test_settings):
        client = _make_client(
            method="private_key_jwt",
            public_jwk=None,
        )
        with pytest.raises(HTTPException) as ei:
            verify_client_assertion(
                _make_request(),
                client,
                client_assertion_type=CLIENT_ASSERTION_TYPE_JWT_BEARER,
                client_assertion="any.token.value",
            )
        assert ei.value.detail["error_code"] == "missing_jwk"
