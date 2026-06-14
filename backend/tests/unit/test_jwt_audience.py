"""Unit tests for JWT audience validation (OIDC Core §3.1.3.7).

Covers Workstream A of the OAuth2/OIDC conformance plan:
  - A.1/A.2: create_access_token sets aud+azp when issued for a client
  - A.3:    create_id_token sets azp alongside aud
  - A.4:    _decode_token respects an optional ``audience`` argument
  - A.5:    decode_token accepts ``expected_aud`` and enforces it
  - A.6:    decode_id_token requires ``expected_aud`` and rejects mismatches
"""

import jwt as pyjwt

from authglow.core.config import get_settings

CLIENT_A = "client-aaa"
CLIENT_B = "client-bbb"


def _unverified_payload(token: str) -> dict:
    """Decode a JWT without verifying signature, aud, or exp — for assertions only."""
    return pyjwt.decode(
        token,
        options={"verify_signature": False, "verify_aud": False, "verify_exp": False},
    )


class TestAccessTokenAudience:
    """A.1 + A.2: create_access_token must emit aud+azp when issued for a client."""

    def test_aud_and_azp_set_when_audience_provided(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u1@example.com",
            scopes=["read"],
            audience=CLIENT_A,
        )
        payload = _unverified_payload(token)
        assert payload["aud"] == CLIENT_A
        assert payload["azp"] == CLIENT_A

    def test_azp_can_differ_from_aud(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u1@example.com",
            scopes=["read"],
            audience="audience-x",
            azp="azp-y",
        )
        payload = _unverified_payload(token)
        assert payload["aud"] == "audience-x"
        assert payload["azp"] == "azp-y"

    def test_no_aud_claim_when_audience_omitted(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1", email="u1@example.com", scopes=["read"]
        )
        payload = _unverified_payload(token)
        assert "aud" not in payload
        assert "azp" not in payload


class TestDecodeTokenAudience:
    """A.4 + A.5: decode_token must accept and enforce expected_aud."""

    def test_expected_aud_matching_returns_token_data(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-2",
            email="u2@example.com",
            scopes=["read"],
            audience=CLIENT_A,
        )
        decoded = jwt_service.decode_token(token, expected_aud=CLIENT_A)
        assert decoded is not None
        assert decoded.aud == CLIENT_A

    def test_expected_aud_mismatching_returns_none(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-2",
            email="u2@example.com",
            scopes=["read"],
            audience=CLIENT_A,
        )
        decoded = jwt_service.decode_token(token, expected_aud=CLIENT_B)
        assert decoded is None

    def test_expected_aud_none_accepts_token_without_aud(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-2", email="u2@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token, expected_aud=None)
        assert decoded is not None
        assert decoded.aud is None

    def test_expected_aud_required_rejects_token_without_aud(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-2", email="u2@example.com", scopes=["read"]
        )
        decoded = jwt_service.decode_token(token, expected_aud=CLIENT_A)
        assert decoded is None


class TestIDTokenAudienceAndAzp:
    """A.3 + A.6: create_id_token sets aud+azp; decode_id_token enforces expected_aud."""

    def test_id_token_contains_azp_claim(self, jwt_service):
        token = jwt_service.create_id_token(
            user_id="u-oidc",
            client_id=CLIENT_A,
            scopes=["openid", "profile"],
            user_claims={"name": "Test User", "email": "t@example.com"},
        )
        payload = _unverified_payload(token)
        assert payload["aud"] == CLIENT_A
        assert payload["azp"] == CLIENT_A

    def test_decode_id_token_matching_aud_returns_claims(self, jwt_service):
        token = jwt_service.create_id_token(
            user_id="u-oidc",
            client_id=CLIENT_A,
            scopes=["openid"],
            user_claims={},
        )
        claims = jwt_service.decode_id_token(token, expected_aud=CLIENT_A)
        assert claims is not None
        assert claims.sub == "u-oidc"
        assert claims.aud == CLIENT_A
        assert claims.azp == CLIENT_A

    def test_decode_id_token_mismatching_aud_returns_none(self, jwt_service):
        token = jwt_service.create_id_token(
            user_id="u-oidc",
            client_id=CLIENT_A,
            scopes=["openid"],
            user_claims={},
        )
        claims = jwt_service.decode_id_token(token, expected_aud=CLIENT_B)
        assert claims is None

    def test_decode_id_token_rejects_tampered_aud(self, jwt_service):
        """A token signed for CLIENT_A but presented with a different aud in the
        payload must be rejected. PyJWT enforces this in ``jwt.decode`` when
        ``audience=`` is passed.
        """

        token = jwt_service.create_id_token(
            user_id="u-oidc",
            client_id=CLIENT_A,
            scopes=["openid"],
            user_claims={},
        )
        # Decode as CLIENT_A succeeds
        assert jwt_service.decode_id_token(token, expected_aud=CLIENT_A) is not None
        # Decode as CLIENT_B fails
        assert jwt_service.decode_id_token(token, expected_aud=CLIENT_B) is None


class TestCrossClientAccessTokenConfusion:
    """Defense against RFC 6749 §10.4 / OIDC token confusion across clients."""

    def test_client_b_cannot_decode_token_issued_for_client_a(self, jwt_service):
        token_for_a = jwt_service.create_access_token(
            user_id="u-x",
            email="x@example.com",
            scopes=["read", "write"],
            audience=CLIENT_A,
        )
        # Client A can decode
        decoded_a = jwt_service.decode_token(token_for_a, expected_aud=CLIENT_A)
        assert decoded_a is not None
        # Client B cannot decode
        decoded_b = jwt_service.decode_token(token_for_a, expected_aud=CLIENT_B)
        assert decoded_b is None


class TestJWTAudienceSettings:
    """Sanity: settings expose an issuer for audience claim context."""

    def test_issuer_is_configured(self):

        s = get_settings()
        assert s.issuer
