"""Tests for the ``extra_claims`` plumbing on JWT issuance.

Focused on the contract between :class:`ClaimPolicyService`
and :class:`JWTService`:

* ``extra_claims`` are merged into the access token payload
  under their resolved claim name.
* The same dict is merged into the ID token payload (when
  ``create_id_token`` is called) with the same reserved-claim
  filter.
* Reserved claims (``iss``, ``sub``, ``exp``, ``iat``,
  ``jti``, ``aud``, ``azp``, ``cnf``, ``token_type``) cannot
  be overridden by ``extra_claims`` — the JWT service is the
  single source of truth for the cryptographic anchors.
* ``TokenData.extra_claims`` (the decode-side view) carries
  every non-reserved claim and the standard OIDC fields
  (email, scope-style fields) are kept on the typed
  attributes.

These tests use the ``jwt_service`` fixture (a fully
initialised JWT service against the test keyring) and
**do not** mock the ClaimPolicyService — the integration
test file ``tests/integration/test_rbac_jwt_injection.py``
covers the service wiring.
"""

import base64
import json

import jwt as pyjwt

from authglow.services.jwt import INTERNAL_AUDIENCE, _RESERVED_CLAIMS


def _decode_payload(token: str) -> dict:
    parts = token.split(".")
    payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


class TestExtraClaimsAccessToken:
    def test_extra_claims_merged_under_resolved_name(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid", "read"],
            extra_claims={
                "https://authglow/claims/tenant_id": "acme",
                "https://authglow/claims/roles": ["admin", "developer"],
            },
        )
        payload = _decode_payload(token)
        assert payload["https://authglow/claims/tenant_id"] == "acme"
        assert payload["https://authglow/claims/roles"] == ["admin", "developer"]

    def test_no_extra_claims_means_no_custom_claims(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1", email="u@test.com", scopes=["openid"]
        )
        payload = _decode_payload(token)
        # No namespaced custom claims (no https:// prefix on
        # any claim other than the JWT-service-owned ones).
        custom_keys = [
            k for k in payload.keys() if k.startswith("https://") and k not in payload
        ]
        # The standard owned-claims list:
        owned = {"iss", "sub", "aud", "exp", "iat", "jti", "azp", "cnf", "token_type",
                 "scopes", "email", "https://authglow.example.com/claims/roles",
                 "https://authglow.example.com/claims/permissions"}
        # When no extra_claims is passed, the payload has only
        # the JWT-service-owned claims + email + scopes.
        unexpected = set(payload.keys()) - owned
        assert unexpected == set(), f"Unexpected claims: {unexpected}"

    def test_extra_claims_none_treated_as_no_claims(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid"],
            extra_claims=None,
        )
        # No exception, token still valid
        data = jwt_service.decode_token(token)
        assert data is not None
        assert data.extra_claims in (None, {})

    def test_extra_claims_none_value_excluded(self, jwt_service):
        """A value of ``None`` in the dict is treated as "do not
        emit" — same as omitting the key."""
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid"],
            extra_claims={"https://authglow/x": None},
        )
        payload = _decode_payload(token)
        assert "https://authglow/x" not in payload


class TestExtraClaimsReservedFilter:
    def test_sub_cannot_be_overridden(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="real-sub",
            email="u@test.com",
            scopes=["openid"],
            extra_claims={"sub": "FAKE-SUB"},
        )
        payload = _decode_payload(token)
        assert payload["sub"] == "real-sub"

    def test_iss_cannot_be_overridden(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid"],
            extra_claims={"iss": "https://evil.example.com"},
        )
        payload = _decode_payload(token)
        assert payload["iss"] != "https://evil.example.com"

    def test_aud_cannot_be_overridden(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid"],
            audience="real-aud",
            extra_claims={"aud": "https://evil.example.com"},
        )
        payload = _decode_payload(token)
        assert payload["aud"] == "real-aud"

    def test_jti_cannot_be_overridden(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u@test.com",
            scopes=["openid"],
            extra_claims={"jti": "FAKE-JTI"},
        )
        payload = _decode_payload(token)
        assert payload["jti"] != "FAKE-JTI"
        # And it parses as a valid UUID
        pyjwt.decode(
            token,
            options={"verify_signature": False},
            algorithms=["RS256"],
        )


class TestExtraClaimsIDToken:
    def test_extra_claims_merged_into_id_token(self, jwt_service):
        token = jwt_service.create_id_token(
            user_id="u-id",
            client_id="client-1",
            scopes=["openid"],
            user_claims={},
            extra_claims={
                "https://authglow.example.com/claims/tenant_id": "acme",
            },
        )
        payload = _decode_payload(token)
        assert payload["https://authglow.example.com/claims/tenant_id"] == "acme"

    def test_id_token_reserved_filter_applies(self, jwt_service):
        """The ID token's ``sub`` and ``aud`` cannot be
        overridden by ``extra_claims`` — same protection as
        the access token."""
        token = jwt_service.create_id_token(
            user_id="real-sub",
            client_id="real-client",
            scopes=["openid"],
            user_claims={},
            extra_claims={"sub": "FAKE", "aud": "FAKE-AUD"},
        )
        payload = _decode_payload(token)
        assert payload["sub"] == "real-sub"
        assert payload["aud"] == "real-client"


class TestTokenDataExtraClaimsDecode:
    def test_decode_exposes_extra_claims_dict(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-rt",
            email="rt@test.com",
            scopes=["openid"],
            extra_claims={
                "https://authglow/claims/tenant_id": "acme",
                "https://authglow/claims/roles": ["admin"],
            },
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.extra_claims is not None
        assert decoded.extra_claims["https://authglow/claims/tenant_id"] == "acme"
        assert decoded.extra_claims["https://authglow/claims/roles"] == ["admin"]
        # Reserved fields are NOT in extra_claims — they live
        # on the typed TokenData attributes
        for reserved in _RESERVED_CLAIMS:
            assert reserved not in (decoded.extra_claims or {})

    def test_decode_keeps_typed_claims_on_fields(self, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u-typed",
            email="typed@test.com",
            scopes=["openid", "read"],
            audience=INTERNAL_AUDIENCE,
            extra_claims={"https://authglow/claims/x": "y"},
        )
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "u-typed"
        assert decoded.email == "typed@test.com"
        assert decoded.aud == INTERNAL_AUDIENCE
        assert "openid" in decoded.scopes
        # ``email`` is kept on the typed field, NOT in extra_claims
        assert "email" not in (decoded.extra_claims or {})


class TestCreateTokenResponseExtraClaims:
    def test_create_token_response_forwards_extra_claims(self, jwt_service):
        response = jwt_service.create_token_response(
            user_id="u-tr",
            email="tr@test.com",
            scopes=["openid"],
            audience="client-1",
            extra_claims={"https://authglow/claims/tenant_id": "acme"},
        )
        decoded = jwt_service.decode_token(response.access_token)
        assert decoded is not None
        assert decoded.extra_claims is not None
        assert decoded.extra_claims["https://authglow/claims/tenant_id"] == "acme"
        assert decoded.aud == "client-1"
