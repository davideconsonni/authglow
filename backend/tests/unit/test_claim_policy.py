"""Unit tests for the Claim Policy service layer.

Covers the model validation (claim name URI enforcement,
duplicate detection, source_config / source coherence), the
default rule set, scope-gating, target filtering, source
resolution for every supported source, the template helpers,
and the API key claim policy (merge semantics + API_KEY_FIELD
source). The file-backed repository is tested separately in
``tests/unit/repositories/file/test_claim_policy.py`` and the
round-trip JWT plumbing in
``tests/integration/test_rbac_jwt_injection.py``.
"""

from __future__ import annotations

import asyncio
from typing import List
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from authglow.core.config import Settings
from authglow.models.api_key import APIKey
from authglow.models.claim_policy import (
    BUILTIN_TEMPLATES,
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
    ClaimTemplate,
    ClientClaimPolicy,
    OIDC_STANDARD_CLAIMS,
    render_template_claim_name,
)
from authglow.models.user import User
from authglow.services.claim_policy import ClaimPolicyService, RESERVED_CLAIMS
from authglow.services.password import hash_password


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(coro):
    """Run an async coroutine via ``asyncio.run`` — the
    :class:`ClaimPolicyService` only does async I/O when
    consulting the repositories, so a fresh per-test loop
    keeps the tests independent."""
    return asyncio.run(coro)


def _make_user(**overrides) -> User:
    defaults: dict = {
        "id": "u-1",
        "email": "u@test.com",
        "hashed_password": hash_password("TestP@ss123!"),
        "is_active": True,
        "scopes": ["read"],
    }
    defaults.update(overrides)
    return User(**defaults)


def _make_api_key(**overrides) -> APIKey:
    """Build an ``APIKey`` with sensible defaults for tests."""
    defaults: dict = {
        "key_id": "ak-test-1",
        "user_id": "u-1",
        "name": "Production key",
        "key_prefix": "ak_ABCDEFGHIJ",
        "key_hash": "$2b$12$dummyhash",
        "scopes": ["read", "write"],
        "is_active": True,
        "allowed_ips": ["10.0.0.0/24"],
        "tier": "production",
        "created_by": "u-1",
    }
    defaults.update(overrides)
    return APIKey(**defaults)


def _make_api_key_claim_policy(api_key_id: str, rules: List[ClaimRule]):
    """Build an APIKeyClaimPolicy without the runtime-annotation
    dependency on the imported symbol (imported lazily)."""
    from authglow.models.api_key_claim_policy import APIKeyClaimPolicy

    return APIKeyClaimPolicy(api_key_id=api_key_id, rules=rules)


# ---------------------------------------------------------------------------
# Model — claim name validation
# ---------------------------------------------------------------------------


class TestClaimNameValidation:
    def test_standard_oidc_claim_is_accepted(self):
        for name in ("sub", "email", "name", "given_name", "scope", "client_id"):
            ClaimRule(
                claim_name=name,
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="x"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_non_standard_plain_name_rejected(self):
        with pytest.raises(ValueError, match="must be a URI"):
            ClaimRule(
                claim_name="tenant_id",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="x"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_https_uri_accepted(self):
        ClaimRule(
            claim_name="https://authglow/tenant_id",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="x"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )

    def test_urn_uri_accepted(self):
        ClaimRule(
            claim_name="urn:example:claim:foo",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="x"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )

    def test_empty_claim_name_rejected(self):
        with pytest.raises(ValueError, match="must not be empty"):
            ClaimRule(
                claim_name="",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="x"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_include_in_must_be_non_empty(self):
        with pytest.raises(ValueError, match="include_in"):
            ClaimRule(
                claim_name="https://authglow/x",
                source=ClaimSource.STATIC,
                source_config=ClaimSourceConfig(value="x"),
                include_in=[],
            )


class TestSourceConfigCoherence:
    def test_user_field_requires_user_field_config(self):
        with pytest.raises(ValueError, match="user_field"):
            ClaimRule(
                claim_name="https://authglow/tenant",
                source=ClaimSource.USER_FIELD,
                source_config=ClaimSourceConfig(),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_static_allows_none_value_as_emit_nothing(self):
        rule = ClaimRule(
            claim_name="https://authglow/env",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        assert rule.source_config.value is None

    def test_rbac_roles_takes_no_config(self):
        ClaimRule(
            claim_name="https://authglow/roles",
            source=ClaimSource.RBAC_ROLES,
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )

    def test_rbac_roles_with_extra_config_rejected(self):
        with pytest.raises(ValueError, match="takes no source_config"):
            ClaimRule(
                claim_name="https://authglow/roles",
                source=ClaimSource.RBAC_ROLES,
                source_config=ClaimSourceConfig(value="x"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_api_key_field_requires_field_config(self):
        with pytest.raises(ValueError, match="api_key_field"):
            ClaimRule(
                claim_name="https://authglow/x",
                source=ClaimSource.API_KEY_FIELD,
                source_config=ClaimSourceConfig(),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_api_key_field_with_unknown_field_rejected(self):
        with pytest.raises(ValidationError):
            ClaimRule(
                claim_name="https://authglow/x",
                source=ClaimSource.API_KEY_FIELD,
                source_config=ClaimSourceConfig(api_key_field="nonsense"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_rbac_with_api_key_field_rejected(self):
        with pytest.raises(ValueError, match="takes no source_config"):
            ClaimRule(
                claim_name="https://authglow/roles",
                source=ClaimSource.RBAC_ROLES,
                source_config=ClaimSourceConfig(api_key_field="name"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )


class TestPolicyNoDuplicateClaimNames:
    def test_duplicate_claim_name_rejected(self):
        rule = ClaimRule(
            claim_name="https://authglow/x",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value=1),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        with pytest.raises(ValueError, match="Duplicate claim_name"):
            ClientClaimPolicy(client_id="c1", rules=[rule, rule])


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------


class TestBuiltinTemplates:
    def test_templates_have_unique_ids(self):
        ids = [t.id for t in BUILTIN_TEMPLATES]
        assert len(ids) == len(set(ids))

    def test_templates_use_relative_claim_names(self):
        for t in BUILTIN_TEMPLATES:
            assert ":" not in t.claim_name, (
                f"Template {t.id!r} should use a relative claim "
                f"name (resolved against claim_namespace at apply time), "
                f"got {t.claim_name!r}"
            )

    def test_render_template_against_namespace(self):
        ns = "https://authglow.example.com/claims"
        assert render_template_claim_name("roles", ns) == f"{ns}/roles"
        assert render_template_claim_name("https://other/x", ns) == "https://other/x"

    def test_render_template_relative_against_empty_namespace_raises(self):
        with pytest.raises(ValueError, match="claim_namespace must be configured"):
            render_template_claim_name("roles", "")

    def test_apply_api_key_template_resolves_claim_name(self, test_settings):
        svc = ClaimPolicyService()
        for template_id in (
            "api-key-name",
            "api-key-prefix",
            "api-key-scopes",
            "api-key-allowed-ips",
            "api-key-tier",
        ):
            rule = svc.apply_template(template_id)
            assert rule.claim_name.startswith(test_settings.claim_namespace)
            assert rule.source == ClaimSource.API_KEY_FIELD


# ---------------------------------------------------------------------------
# Service — default rules + build_claims (first-party / OAuth client)
# ---------------------------------------------------------------------------


class TestDefaultRules:
    def test_default_rules_are_namespaced(self, test_settings):
        svc = ClaimPolicyService()
        rules = svc._default_rules()
        ns = test_settings.claim_namespace.rstrip("/")
        assert any(r.claim_name == f"{ns}/roles" for r in rules)
        assert any(r.claim_name == f"{ns}/permissions" for r in rules)

    def test_default_rules_target_access_token_only(self, test_settings):
        svc = ClaimPolicyService()
        rules = svc._default_rules()
        for r in rules:
            assert r.include_in == [ClaimTarget.ACCESS_TOKEN]


class TestBuildClaimsFirstParty:
    def test_first_party_returns_default_rbac_claims(self, test_settings):
        svc = ClaimPolicyService()
        user = _make_user()
        claims = _run(
            svc.build_claims(
                user, client_id=None, scopes=["read"], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        ns = test_settings.claim_namespace.rstrip("/")
        assert f"{ns}/roles" in claims
        assert f"{ns}/permissions" in claims
        assert claims[f"{ns}/roles"] == []
        assert claims[f"{ns}/permissions"] == []

    def test_first_party_id_token_target_omits_default_claims(self, test_settings):
        """The default rule set is target=ACCESS_TOKEN only —
        ID token claims must come from a saved policy with
        include_in=[ID_TOKEN]."""
        svc = ClaimPolicyService()
        user = _make_user()
        claims = _run(
            svc.build_claims(
                user, client_id=None, scopes=["openid"], target=ClaimTarget.ID_TOKEN
            )
        )
        assert claims == {}


class TestBuildClaimsClientWithPolicy:
    def test_saved_policy_overrides_default(self, test_settings):
        svc = ClaimPolicyService()
        saved = ClientClaimPolicy(
            client_id="c1",
            rules=[
                ClaimRule(
                    claim_name="https://example/custom",
                    source=ClaimSource.STATIC,
                    source_config=ClaimSourceConfig(value="hello"),
                    include_in=[ClaimTarget.ACCESS_TOKEN],
                )
            ],
        )
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(return_value=saved)
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert claims.get("https://example/custom") == "hello"
        ns = test_settings.claim_namespace.rstrip("/")
        assert f"{ns}/roles" not in claims
        assert f"{ns}/permissions" not in claims

    def test_missing_policy_falls_back_to_default(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(return_value=None)
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c-no-policy", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        ns = test_settings.claim_namespace.rstrip("/")
        assert f"{ns}/roles" in claims
        assert f"{ns}/permissions" in claims


class TestBuildClaimsTargetFilter:
    def test_target_filter_excludes_other_targets(self, test_settings):
        svc = ClaimPolicyService()
        rule_id_token = ClaimRule(
            claim_name="https://example/id-only",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="id-value"),
            include_in=[ClaimTarget.ID_TOKEN],
        )
        rule_access = ClaimRule(
            claim_name="https://example/access-only",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="access-value"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(client_id="c1", rules=[rule_id_token, rule_access])
        )
        access_claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "https://example/id-only" not in access_claims
        assert access_claims["https://example/access-only"] == "access-value"
        id_claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ID_TOKEN
            )
        )
        assert "https://example/access-only" not in id_claims
        assert id_claims["https://example/id-only"] == "id-value"


class TestBuildClaimsScopeGating:
    def test_required_scope_excludes_claim_when_missing(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://example/scope-gated",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="x"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
            required_scope="special",
        )
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(client_id="c1", rules=[rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=["read"], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "https://example/scope-gated" not in claims
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=["special"], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert claims["https://example/scope-gated"] == "x"


class TestBuildClaimsReservedFilter:
    def test_reserved_claims_filtered_from_extra_claims(self, test_settings):
        """If a policy tries to write a reserved claim (e.g.
        ``sub``), the service silently skips it — the JWT
        service owns these."""
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="iss",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="evil"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(client_id="c1", rules=[rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "iss" not in claims


# ---------------------------------------------------------------------------
# Service — source resolution (OAuth client path)
# ---------------------------------------------------------------------------


class TestResolveUserField:
    def test_user_field_with_value(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/first_name",
                        source=ClaimSource.USER_FIELD,
                        source_config=ClaimSourceConfig(user_field="first_name"),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        user = _make_user(first_name="Jane")
        claims = _run(
            svc.build_claims(user, client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN)
        )
        assert claims["https://authglow/first_name"] == "Jane"

    def test_user_field_missing_attribute_yields_no_claim(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/first_name",
                        source=ClaimSource.USER_FIELD,
                        source_config=ClaimSourceConfig(user_field="nonexistent"),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "https://authglow/first_name" not in claims

    def test_user_field_with_no_user_yields_no_claim(self, test_settings):
        """``client_credentials`` grant: no user, USER_FIELD
        rules produce nothing."""
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/first_name",
                        source=ClaimSource.USER_FIELD,
                        source_config=ClaimSourceConfig(user_field="first_name"),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        claims = _run(
            svc.build_claims(
                user=None, client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "https://authglow/first_name" not in claims


class TestResolveStatic:
    def test_static_value_emitted(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/environment",
                        source=ClaimSource.STATIC,
                        source_config=ClaimSourceConfig(value="prod"),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert claims["https://authglow/environment"] == "prod"

    def test_static_none_value_excluded(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/environment",
                        source=ClaimSource.STATIC,
                        source_config=ClaimSourceConfig(value=None),
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        claims = _run(
            svc.build_claims(
                _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
            )
        )
        assert "https://authglow/environment" not in claims


class TestResolveRBAC:
    def test_rbac_roles_emitted_from_user_assignments(self, test_settings):
        svc = ClaimPolicyService()
        svc._repository = MagicMock()
        svc._repository.get_by_client = AsyncMock(
            return_value=ClientClaimPolicy(
                client_id="c1",
                rules=[
                    ClaimRule(
                        claim_name="https://authglow/roles",
                        source=ClaimSource.RBAC_ROLES,
                        include_in=[ClaimTarget.ACCESS_TOKEN],
                    )
                ],
            )
        )
        from authglow.models.rbac import Role, UserRole
        from authglow.services import rbac as rbac_module

        original = rbac_module.RBACService
        stub = MagicMock()

        async def _perms(_uid):
            return set()

        async def _roles(_uid):
            return [UserRole(user_id="u-1", role_id="r1", assigned_by="test")]

        async def _role(_rid):
            return Role(role_id="r1", name="developer", permissions=[])

        stub.get_user_permissions = _perms
        stub.get_user_roles = _roles
        stub.get_role = _role
        rbac_module.RBACService = lambda: stub
        try:
            claims = _run(
                svc.build_claims(
                    _make_user(), client_id="c1", scopes=[], target=ClaimTarget.ACCESS_TOKEN
                )
            )
        finally:
            rbac_module.RBACService = original
        assert claims["https://authglow/roles"] == ["developer"]


# ---------------------------------------------------------------------------
# Service — template helpers
# ---------------------------------------------------------------------------


class TestApplyTemplate:
    def test_apply_template_resolves_claim_name(self, test_settings):
        svc = ClaimPolicyService()
        rule = svc.apply_template("rbac-roles")
        assert rule.claim_name == f"{test_settings.claim_namespace}/roles"
        assert rule.source == ClaimSource.RBAC_ROLES

    def test_apply_template_overrides_include_in(self, test_settings):
        svc = ClaimPolicyService()
        rule = svc.apply_template(
            "rbac-roles", include_in=[ClaimTarget.ACCESS_TOKEN, ClaimTarget.ID_TOKEN]
        )
        assert ClaimTarget.ACCESS_TOKEN in rule.include_in
        assert ClaimTarget.ID_TOKEN in rule.include_in

    def test_apply_unknown_template_raises(self, test_settings):
        svc = ClaimPolicyService()
        with pytest.raises(ValueError, match="Unknown claim template"):
            svc.apply_template("nope")

    def test_list_templates_returns_copy(self, test_settings):
        svc = ClaimPolicyService()
        templates = svc.list_templates()
        assert len(templates) >= 6
        templates.append("garbage")
        assert all(t.id != "garbage" for t in BUILTIN_TEMPLATES)


# ---------------------------------------------------------------------------
# Service — write path (OAuth client)
# ---------------------------------------------------------------------------


class TestSaveAndDelete:
    def test_save_policy_creates_new(self, test_settings):
        repo = MagicMock()
        repo.get_by_client = AsyncMock(return_value=None)
        repo.save = AsyncMock()
        svc = ClaimPolicyService(repository=repo)
        rule = ClaimRule(
            claim_name="https://authglow/x",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value=1),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        saved = _run(svc.save_policy("c1", [rule]))
        assert saved.client_id == "c1"
        assert len(saved.rules) == 1
        repo.save.assert_awaited_once()

    def test_save_policy_empty_rules_deletes(self, test_settings):
        repo = MagicMock()
        repo.delete = AsyncMock(return_value=True)
        svc = ClaimPolicyService(repository=repo)
        saved = _run(svc.save_policy("c1", []))
        repo.delete.assert_awaited_once_with("c1")
        assert len(saved.rules) >= 1

    def test_delete_policy_returns_bool(self, test_settings):
        repo = MagicMock()
        repo.delete = AsyncMock(return_value=True)
        svc = ClaimPolicyService(repository=repo)
        result = _run(svc.delete_policy("c1"))
        assert result is True


# ---------------------------------------------------------------------------
# Service — API key claim policy (merge semantics)
# ---------------------------------------------------------------------------


class TestBuildClaimsAPIKeyReplace:
    def test_api_key_emits_no_extra_claims_when_no_policy_saved(self, test_settings):
        """No saved API key policy → no extra claims (the
        namespaced RBAC roles + permissions defaults are NOT
        auto-applied to API keys; the admin opts in via the
        Claims tab)."""
        svc = ClaimPolicyService()
        api_key = _make_api_key()
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id=api_key.key_id,
                api_key=api_key,
                scopes=["read", "write"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        ns = test_settings.claim_namespace.rstrip("/")
        assert claims == {}
        assert f"{ns}/roles" not in claims
        assert f"{ns}/permissions" not in claims

    def test_saved_api_key_policy_replaces_default(self, test_settings):
        """A saved API key policy REPLACES the default rule set
        — only the saved claims are emitted, no implicit RBAC
        defaults are added on top."""
        svc = ClaimPolicyService()
        api_key = _make_api_key()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_name",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="name"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy(api_key.key_id, [rule])
        )

        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id=api_key.key_id,
                api_key=api_key,
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        ns = test_settings.claim_namespace.rstrip("/")
        assert claims == {
            "https://authglow.example.com/claims/api_key_name": "Production key"
        }
        assert f"{ns}/roles" not in claims
        assert f"{ns}/permissions" not in claims

    def test_api_key_saved_rule_emits_directly(self, test_settings):
        """A saved rule with the same claim_name as the legacy
        RBAC default is emitted as-is — there is no default
        rule to compete with (REPLACE, not MERGE)."""
        svc = ClaimPolicyService()
        api_key = _make_api_key()
        ns = test_settings.claim_namespace.rstrip("/")
        rule = ClaimRule(
            claim_name=f"{ns}/roles",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value=["custom-from-saved"]),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy(api_key.key_id, [rule])
        )

        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id=api_key.key_id,
                api_key=api_key,
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert claims == {f"{ns}/roles": ["custom-from-saved"]}
        assert f"{ns}/permissions" not in claims

    def test_api_key_id_without_api_key_instance_skips_api_key_field(
        self, test_settings
    ):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_name",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="name"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-x", [rule])
        )

        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-x",
                api_key=None,
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert (
            "https://authglow.example.com/claims/api_key_name" not in claims
        )

    def test_client_id_and_api_key_id_are_mutually_exclusive(self, test_settings):
        svc = ClaimPolicyService()
        with pytest.raises(ValueError, match="at most one"):
            _run(
                svc.build_claims(
                    _make_user(),
                    client_id="c1",
                    api_key_id="ak-1",
                    scopes=["read"],
                    target=ClaimTarget.ACCESS_TOKEN,
                )
            )


class TestResolveAPIKeyField:
    def test_api_key_field_name(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_name",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="name"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-1", [rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-1",
                api_key=_make_api_key(name="My Production Key"),
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert claims[
            "https://authglow.example.com/claims/api_key_name"
        ] == "My Production Key"

    def test_api_key_field_prefix(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_prefix",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="key_prefix"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-1", [rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-1",
                api_key=_make_api_key(key_prefix="ak_ABCDEFGHIJ"),
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert (
            claims["https://authglow.example.com/claims/api_key_prefix"]
            == "ak_ABCDEFGHIJ"
        )

    def test_api_key_field_scopes(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_scopes",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="scopes"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-1", [rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-1",
                api_key=_make_api_key(scopes=["read", "write"]),
                scopes=["read", "write"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert claims[
            "https://authglow.example.com/claims/api_key_scopes"
        ] == ["read", "write"]

    def test_api_key_field_tier(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_tier",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="tier"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-1", [rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-1",
                api_key=_make_api_key(tier="staging"),
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert (
            claims["https://authglow.example.com/claims/api_key_tier"]
            == "staging"
        )

    def test_api_key_field_tier_unset_yields_no_claim(self, test_settings):
        svc = ClaimPolicyService()
        rule = ClaimRule(
            claim_name="https://authglow.example.com/claims/api_key_tier",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="tier"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc._api_key_repository = MagicMock()
        svc._api_key_repository.get_by_api_key = AsyncMock(
            return_value=_make_api_key_claim_policy("ak-1", [rule])
        )
        claims = _run(
            svc.build_claims(
                _make_user(),
                api_key_id="ak-1",
                api_key=_make_api_key(tier=None),
                scopes=["read"],
                target=ClaimTarget.ACCESS_TOKEN,
            )
        )
        assert (
            "https://authglow.example.com/claims/api_key_tier" not in claims
        )


# ---------------------------------------------------------------------------
# Service — write path (API key)
# ---------------------------------------------------------------------------


class TestAPIKeyPolicySaveDelete:
    def test_save_creates_new(self, test_settings):
        repo = MagicMock()
        repo.get_by_api_key = AsyncMock(return_value=None)
        repo.save = AsyncMock()
        svc = ClaimPolicyService(api_key_repository=repo)
        rule = ClaimRule(
            claim_name="https://authglow/x",
            source=ClaimSource.API_KEY_FIELD,
            source_config=ClaimSourceConfig(api_key_field="name"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        saved = _run(svc.save_api_key_policy("ak-1", [rule]))
        assert saved.api_key_id == "ak-1"
        assert len(saved.rules) == 1
        repo.save.assert_awaited_once()

    def test_save_with_empty_rules_deletes(self, test_settings):
        """Empty rules → the saved policy is removed and the
        synthetic return reflects the no-policy state (empty
        rules, since API key REPLACE semantics drop the
        defaults along with the saved policy)."""
        repo = MagicMock()
        repo.delete = AsyncMock(return_value=True)
        svc = ClaimPolicyService(api_key_repository=repo)
        saved = _run(svc.save_api_key_policy("ak-1", []))
        repo.delete.assert_awaited_once_with("ak-1")
        assert saved.rules == []

    def test_delete_policy_returns_bool(self, test_settings):
        repo = MagicMock()
        repo.delete = AsyncMock(return_value=True)
        svc = ClaimPolicyService(api_key_repository=repo)
        result = _run(svc.delete_api_key_policy("ak-1"))
        assert result is True
