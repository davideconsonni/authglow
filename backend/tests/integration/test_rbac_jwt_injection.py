"""Integration tests for the Claim Policy → JWT pipeline.

Tests the namespaced RBAC claim injection (per OIDC §5.1.2
namespacing requirement) and the ``extra_claims`` plumbing
between :class:`ClaimPolicyService` and
:class:`JWTService`.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.user import User
from authglow.services.password import hash_password


def _decode_payload(token: str) -> dict:
    """Decode a JWT payload without signature verification — the
    test signature uses the project test keyring so the wire
    format can be inspected directly."""
    import base64

    parts = token.split(".")
    payload = parts[1]
    # Base64url padding
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


class TestClaimPolicyEndToEnd:
    def test_default_policy_emits_namespaced_rbac(self, test_settings, jwt_service):
        """No saved policy → the default first-party rule set
        (namespaced RBAC roles + permissions, into the access
        token) is applied."""
        from authglow.models.claim_policy import ClaimTarget
        from authglow.services.claim_policy import ClaimPolicyService

        svc = ClaimPolicyService()
        user = User(
            id="u-default",
            email="default@test.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            scopes=["openid", "read"],
        )
        claims = asyncio.run(
            svc.build_claims(user, client_id=None, scopes=["read"], target=ClaimTarget.ACCESS_TOKEN)
        )
        assert "https://authglow.example.com/claims/roles" in claims
        assert "https://authglow.example.com/claims/permissions" in claims
        assert claims["https://authglow.example.com/claims/roles"] == []
        assert claims["https://authglow.example.com/claims/permissions"] == []

    def test_extra_claims_merged_into_access_token(self, test_settings, jwt_service):
        """``extra_claims`` are merged into the access token
        payload under the resolved (namespaced) claim name."""
        extra_claims = {
            "https://authglow.example.com/claims/tenant_id": "acme",
            "https://authglow.example.com/claims/roles": ["admin", "developer"],
        }
        token = jwt_service.create_access_token(
            user_id="u-1",
            email="u1@test.com",
            scopes=["openid", "read"],
            extra_claims=extra_claims,
        )
        payload = _decode_payload(token)
        assert payload["https://authglow.example.com/claims/tenant_id"] == "acme"
        assert payload["https://authglow.example.com/claims/roles"] == ["admin", "developer"]

    def test_extra_claims_cannot_override_reserved(self, test_settings, jwt_service):
        """``iss``, ``sub``, ``exp``, ``iat``, ``jti``, ``aud``
        cannot be overridden by ``extra_claims`` — the JWT
        service owns the cryptographic anchors.

        The contract is enforced by silently filtering: try
        to override ``sub`` and confirm the token's ``sub``
        is still the real user_id.
        """
        token = jwt_service.create_access_token(
            user_id="u-real-sub",
            email="u@test.com",
            scopes=["openid"],
            extra_claims={
                "sub": "FAKE-SUB",  # must be ignored
                "https://authglow/claims/tenant_id": "acme",
            },
        )
        payload = _decode_payload(token)
        assert payload["sub"] == "u-real-sub"
        assert payload["https://authglow/claims/tenant_id"] == "acme"

    def test_extra_claims_merged_into_id_token(self, test_settings, jwt_service):
        """The ID token accepts the same ``extra_claims``
        parameter and the namespaced RBAC claims land in the
        OIDC ID token payload as well."""
        extra_claims = {
            "https://authglow.example.com/claims/tenant_id": "tenant-42",
        }
        token = jwt_service.create_id_token(
            user_id="u-id",
            client_id="client-1",
            scopes=["openid"],
            user_claims={},
            extra_claims=extra_claims,
        )
        payload = _decode_payload(token)
        assert payload["https://authglow.example.com/claims/tenant_id"] == "tenant-42"
        # Standard OIDC claims still in place
        assert payload["iss"] == test_settings.issuer
        assert payload["sub"] == "u-id"
        assert payload["aud"] == "client-1"

    def test_decoded_extra_claims_round_trip(self, test_settings, jwt_service):
        """``decode_token`` exposes namespaced custom claims via
        :attr:`TokenData.extra_claims` (a free-form dict)."""
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
        # Reserved / typed fields are NOT in extra_claims
        assert "iss" not in decoded.extra_claims
        assert "sub" not in decoded.extra_claims
        assert "email" not in decoded.extra_claims


class TestClaimPolicyScopeGating:
    def test_required_scope_filters_claim_out(self, test_settings, jwt_service):
        """A rule with ``required_scope`` is skipped when the
        requested scope is not in the granted set."""
        from authglow.models.claim_policy import (
            BUILTIN_TEMPLATES,
            ClaimRule,
            ClaimSource,
            ClaimTarget,
        )
        from authglow.services.claim_policy import ClaimPolicyService

        # Build a one-rule policy that requires scope "roles".
        rule = ClaimRule(
            claim_name="https://authglow/claims/roles",
            source=ClaimSource.RBAC_ROLES,
            include_in=[ClaimTarget.ACCESS_TOKEN],
            required_scope="roles",
        )
        policy_service = ClaimPolicyService()
        # Patch the repository to return our custom policy
        policy_service._repository = MagicMock()
        policy_service._repository.get_by_client = AsyncMock(
            return_value=MagicMock(rules=[rule])
        )

        async def _run():
            user = User(
                id="u-scope",
                email="s@test.com",
                hashed_password=hash_password("TestP@ss123!"),
                is_active=True,
                scopes=["read"],
            )
            # Without "roles" scope → claim excluded
            claims = await policy_service.build_claims(
                user, client_id="x", scopes=["read"], target=ClaimTarget.ACCESS_TOKEN
            )
            assert "https://authglow/claims/roles" not in claims
            # With "roles" scope → claim included (empty list,
            # because the user has no roles assigned in this
            # test)
            claims = await policy_service.build_claims(
                user, client_id="x", scopes=["roles"], target=ClaimTarget.ACCESS_TOKEN
            )
            assert "https://authglow/claims/roles" in claims

        asyncio.run(_run())


class TestClaimPolicyBuiltinTemplates:
    def test_templates_resolve_against_namespace(self, test_settings, jwt_service):
        """The relative claim name of a template is expanded
        against ``settings.claim_namespace`` at apply time."""
        from authglow.services.claim_policy import ClaimPolicyService

        svc = ClaimPolicyService()
        rule = svc.apply_template("rbac-roles")
        assert rule.claim_name == f"{test_settings.claim_namespace}/roles"
        assert rule.source.value == "rbac_roles"

    def test_unknown_template_id_raises(self, test_settings):
        from authglow.services.claim_policy import ClaimPolicyService

        svc = ClaimPolicyService()
        with pytest.raises(ValueError):
            svc.apply_template("does-not-exist")
