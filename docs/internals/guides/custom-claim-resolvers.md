# Custom Claim Resolvers

How to embed externally-computed claims (CRM tier, feature flags,
entitlements, …) into AuthGlow tokens without touching the core.

## Overview

Claim policies are declarative rules (`ClaimRule`) evaluated at token
issuance by `ClaimPolicyService.build_claims()`. Six built-in sources
cover the common cases (`user_field`, `rbac_roles`, `rbac_permissions`,
`static`, `jwt_meta`, `api_key_field`). For everything else there is
a seventh source:

- **`custom`** — delegates to an async resolver function you register
  at startup via `register_claim_resolver(name, fn)`.

A rule with `source: custom` carries:

| Field | Meaning |
|-------|---------|
| `source_config.custom_resolver` | Name the resolver was registered under (required). |
| `source_config.custom_config` | Opaque per-rule dict forwarded to the resolver verbatim (optional). Supports `warn_after_s` (slow-log threshold in seconds, default `1.0`). |

## Step 1 — Write the resolver

```python
# plugins/crm_claims.py
import httpx
from authglow.models.claim_policy import ClaimRule
from authglow.services.claim_policy import ClaimResolveContext


async def crm_tier_resolver(rule: ClaimRule, ctx: ClaimResolveContext):
    """Return the CRM tier for the token subject, or None to skip."""
    if ctx.user is None:
        # No subject (e.g. client_credentials grant) — nothing to look up.
        return None
    cfg = rule.source_config.custom_config or {}
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.get(f"https://crm.internal/users/{ctx.user.id}")
        resp.raise_for_status()
        return resp.json().get(cfg.get("crm_field", "tier"))
```

Contract:

- **Signature:** `async def resolver(rule: ClaimRule, ctx: ClaimResolveContext) -> Any`.
- **Return value** becomes the claim value. Return `None` to skip the claim.
- **Never raise to fail issuance:** exceptions are caught, the claim is
  skipped, and a structured `claim_resolver_failed` event is logged.
  Keep resolvers fast and set short HTTP timeouts of your own.
- **`ctx` fields:** `user`, `api_key`, `rbac_roles`, `rbac_permissions`,
  `client_id`, `api_key_id`, `scopes`, `target`. The context is frozen;
  new fields may be added in the future without breaking resolvers.

## Step 2 — Register it at startup

```python
from authglow.services.claim_policy import register_claim_resolver
from plugins.crm_claims import crm_tier_resolver

register_claim_resolver("crm_tier", crm_tier_resolver)
```

The import must run before policies referencing `crm_tier` are saved
and before tokens are issued (e.g. in the app lifespan or your
bootstrap module). Saving a rule with an unregistered name is
rejected with **422**; if the plugin is removed later, issuance
degrades (claim skipped + `claim_resolver_missing` log), never 500.

## Step 3 — Save the rule via the admin API

```http
PUT /api/admin/oauth-clients/{client_id}/claim-policy
Content-Type: application/json

{
  "rules": [
    {
      "claim_name": "https://example.com/claims/tier",
      "source": "custom",
      "source_config": {
        "custom_resolver": "crm_tier",
        "custom_config": { "crm_field": "tier", "warn_after_s": 0.5 }
      },
      "include_in": ["access_token"]
    }
  ]
}
```

Notes:

- `claim_name` must be a URI unless it is a standard OIDC claim
  (OIDC Core §5.1.2, enforced by the model).
- `include_in` selects the targets (`access_token`, `id_token`,
  `userinfo`); `required_scope` optionally gates on an approved scope.
- Reserved claims (`iss`, `sub`, `aud`, …) can never be overridden.

## Observability

All events go to the `authglow.audit` structlog logger as JSON —
stable event names, ready for log queries and dashboards:

| Event | When | Fields |
|-------|------|--------|
| `claim_resolver_slow` | Resolver exceeded `warn_after_s` | `resolver`, `claim_name`, `elapsed_ms`, `threshold_ms` |
| `claim_resolver_failed` | Resolver raised | `resolver`, `claim_name`, `error_type`, `elapsed_ms` |
| `claim_resolver_missing` | No resolver registered under the name | `resolver`, `claim_name` |

## Checklist

1. Resolver is `async`, returns a JSON-serialisable value or `None`.
2. Short timeouts on every outbound call; no retries that outlive token issuance.
3. Registered at startup before first use.
4. Rule saved via admin API (422 on typos/unknown resolver).
5. Dashboard on `claim_resolver_slow` / `claim_resolver_failed` for the new resolver.
