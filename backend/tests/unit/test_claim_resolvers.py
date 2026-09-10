"""Unit tests for pluggable custom claim resolvers.

Covers the ``CUSTOM`` claim source: model coherence (custom_resolver
required, other fields forbidden), save-time rejection of unknown
resolvers, issue-time degradation (missing/failing resolvers skip
the claim, never break issuance), ``custom_config`` passthrough,
and the structured ``claim_resolver_slow`` / ``claim_resolver_failed``
observability events.
"""

import asyncio
from typing import Any, Dict, List
from unittest.mock import AsyncMock

import pytest
from pydantic import ValidationError

from authglow.models.claim_policy import ClaimRule, ClaimSource, ClaimSourceConfig, ClaimTarget
from authglow.services import claim_policy as cp_module
from authglow.services.claim_policy import ClaimPolicyService, register_claim_resolver


def _custom_rule(resolver: str, **config: Any) -> ClaimRule:
    return ClaimRule(
        claim_name="https://authglow.example.com/custom",
        source=ClaimSource.CUSTOM,
        source_config=ClaimSourceConfig(
            custom_resolver=resolver,
            custom_config=dict(config) or None,
        ),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    )


def _service_with_rules(rules: List[ClaimRule]) -> ClaimPolicyService:
    from authglow.models.claim_policy import ClientClaimPolicy

    repo = AsyncMock()
    repo.get_by_client.return_value = ClientClaimPolicy(client_id="c1", rules=rules)
    return ClaimPolicyService(repository=repo)


class TestCustomSourceModel:
    def test_custom_requires_resolver(self):
        with pytest.raises(ValidationError, match="custom_resolver"):
            ClaimRule(
                claim_name="https://authglow.example.com/custom",
                source=ClaimSource.CUSTOM,
                source_config=ClaimSourceConfig(),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_custom_rejects_other_fields(self):
        with pytest.raises(ValidationError, match="CUSTOM"):
            ClaimRule(
                claim_name="https://authglow.example.com/custom",
                source=ClaimSource.CUSTOM,
                source_config=ClaimSourceConfig(custom_resolver="crm", value="literal"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_builtin_rejects_custom_fields(self):
        with pytest.raises(ValidationError, match="custom_resolver"):
            ClaimRule(
                claim_name="https://authglow.example.com/roles",
                source=ClaimSource.RBAC_ROLES,
                source_config=ClaimSourceConfig(custom_resolver="crm"),
                include_in=[ClaimTarget.ACCESS_TOKEN],
            )

    def test_custom_valid(self):
        rule = _custom_rule("crm", crm_field="tier")
        assert rule.source_config.custom_resolver == "crm"
        assert rule.source_config.custom_config == {"crm_field": "tier"}


class TestCustomResolvers:
    async def test_resolver_value_emitted(self, test_settings):
        async def crm_tier(rule, ctx):
            return "enterprise"

        register_claim_resolver("test-crm-tier", crm_tier)
        try:
            svc = _service_with_rules([_custom_rule("test-crm-tier")])
            claims = await svc.build_claims(client_id="c1")
            assert claims == {"https://authglow.example.com/custom": "enterprise"}
        finally:
            cp_module._RESOLVERS.pop("test-crm-tier", None)

    async def test_custom_config_forwarded(self, test_settings):
        seen: Dict[str, Any] = {}

        async def echo_config(rule, ctx):
            seen.update(rule.source_config.custom_config or {})
            return "v"

        register_claim_resolver("test-echo-config", echo_config)
        try:
            svc = _service_with_rules([_custom_rule("test-echo-config", crm_field="tier")])
            await svc.build_claims(client_id="c1")
            assert seen == {"crm_field": "tier"}
        finally:
            cp_module._RESOLVERS.pop("test-echo-config", None)

    async def test_failing_resolver_skips_claim(self, test_settings, capsys):
        async def boom(rule, ctx):
            raise RuntimeError("crm down")

        register_claim_resolver("test-boom", boom)
        try:
            svc = _service_with_rules([_custom_rule("test-boom")])
            claims = await svc.build_claims(client_id="c1")
            assert claims == {}
            assert "claim_resolver_failed" in capsys.readouterr().out
        finally:
            cp_module._RESOLVERS.pop("test-boom", None)

    async def test_missing_resolver_skips_claim(self, test_settings, capsys):
        # Bypass save-time validation via a stubbed repository: a
        # plugin removed after the policy was saved must degrade,
        # never break issuance.
        svc = _service_with_rules([_custom_rule("test-gone")])
        claims = await svc.build_claims(client_id="c1")
        assert claims == {}
        assert "claim_resolver_missing" in capsys.readouterr().out

    async def test_slow_resolver_logged(self, test_settings, capsys):
        async def slow(rule, ctx):
            await asyncio.sleep(0.05)
            return "late"

        register_claim_resolver("test-slow", slow)
        try:
            svc = _service_with_rules([_custom_rule("test-slow", warn_after_s=0.01)])
            claims = await svc.build_claims(client_id="c1")
            assert claims == {"https://authglow.example.com/custom": "late"}
            out = capsys.readouterr().out
            assert "claim_resolver_slow" in out
            assert "test-slow" in out
        finally:
            cp_module._RESOLVERS.pop("test-slow", None)

    async def test_save_rejects_unknown_resolver(self, test_settings):
        svc = ClaimPolicyService(repository=AsyncMock())
        with pytest.raises(ValueError, match="Unknown custom claim resolver"):
            await svc.save_policy("c1", [_custom_rule("test-unknown")])

    async def test_save_api_key_rejects_unknown_resolver(self, test_settings):
        svc = ClaimPolicyService(api_key_repository=AsyncMock())
        with pytest.raises(ValueError, match="Unknown custom claim resolver"):
            await svc.save_api_key_policy("ak-1", [_custom_rule("test-unknown")])

    async def test_builtin_still_emitted(self, test_settings):
        rule = ClaimRule(
            claim_name="https://authglow.example.com/static",
            source=ClaimSource.STATIC,
            source_config=ClaimSourceConfig(value="s"),
            include_in=[ClaimTarget.ACCESS_TOKEN],
        )
        svc = _service_with_rules([rule])
        claims = await svc.build_claims(client_id="c1")
        assert claims == {"https://authglow.example.com/static": "s"}
