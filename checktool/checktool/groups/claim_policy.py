"""Group: per-client / per-key claim policies (admin surface)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from checktool.registry import Group, GroupContext, register_group

REDIRECT_URI = "http://localhost:9999/callback"


def _rule_from_template(template: Dict[str, Any]) -> Dict[str, Any]:
    description = template.get("description")
    return {
        "claim_name": template.get("claim_name"),
        "source": template.get("source"),
        "source_config": template.get("source_config") or {},
        "include_in": template.get("include_in") or [],
        "required_scope": template.get("required_scope"),
        "description": description[:500] if isinstance(description, str) else None,
    }


@register_group
class ClaimPolicyGroup(Group):
    slug = "claim_policy"
    title = "Claim policies"
    description = (
        "Save, read back and delete a custom claim rule on an OAuth client and on an API key."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        key_id: Optional[str] = None
        try:
            templates = ctx.request(
                "The built-in claim templates are listed", "GET", "/api/admin/claim-templates"
            )
            template_list = ctx.json(templates)
            ctx.check(
                "GET /api/admin/claim-templates returns a non-empty list",
                templates.status_code == 200
                and isinstance(template_list, list)
                and bool(template_list),
                ctx.evidence(templates),
            )
            rule = _rule_from_template(template_list[0]) if template_list else None

            created_client = ctx.request(
                "An OAuth client is created to carry the policy",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("policy-client"),
                    "redirect_uris": [REDIRECT_URI],
                    "allowed_scopes": ["openid", "profile", "email", "read", "offline_access"],
                    "grant_types": ["authorization_code", "refresh_token"],
                },
            )
            client_id = ctx.json(created_client).get("client_id")
            ctx.check(
                "The OAuth client for the policy exists",
                created_client.status_code == 201 and bool(client_id),
                ctx.evidence(created_client),
            )

            if client_id and rule:
                self._exercise(
                    ctx,
                    f"/api/admin/oauth-clients/{client_id}/claim-policy",
                    "client",
                    rule,
                )

            created_key = ctx.request(
                "An API key is created to carry the policy",
                "POST",
                "/api/keys",
                json={"name": ctx.name("policy-key"), "scopes": ["read"]},
            )
            key_id = ctx.json(created_key).get("key_id")
            ctx.check(
                "The API key for the policy exists",
                created_key.status_code == 201 and bool(key_id),
                ctx.evidence(created_key),
            )
            if key_id:
                ctx.expose("Claim-policy API key id", key_id, secret=False)
            if key_id and rule:
                self._exercise(
                    ctx,
                    f"/api/admin/api-keys/{key_id}/claim-policy",
                    "API key",
                    rule,
                )
        finally:
            if key_id:
                _delete_key(ctx, key_id)
            if client_id:
                resp = ctx.api.delete(f"/api/oauth-clients/{client_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete test OAuth client {client_id}: HTTP {resp.status_code}"
                    )

    def _exercise(
        self, ctx: GroupContext, path: str, label: str, rule: Dict[str, Any]
    ) -> None:
        initial = ctx.api.get(path)
        body = ctx.json(initial)
        ctx.check(
            f"GET {label} claim-policy returns rules + default_rules",
            initial.status_code == 200
            and isinstance(body.get("rules"), list)
            and isinstance(body.get("default_rules"), list),
            ctx.evidence(initial),
        )

        saved = ctx.api.put(path, json={"rules": [rule]})
        ctx.check(
            f"PUT {label} claim-policy saves a custom policy",
            saved.status_code == 200 and ctx.json(saved).get("is_custom") is True,
            ctx.evidence(saved),
        )

        read_back = ctx.api.get(path)
        names = [
            r.get("claim_name") for r in (ctx.json(read_back).get("rules") or [])
        ]
        ctx.check(
            f"GET {label} claim-policy shows the saved rule",
            ctx.json(read_back).get("is_custom") is True and rule["claim_name"] in names,
            ctx.evidence(read_back),
        )

        deleted = ctx.api.delete(path)
        ctx.check(
            f"DELETE {label} claim-policy reverts to the default",
            deleted.status_code == 204,
            ctx.evidence(deleted),
        )

        after = ctx.api.get(path)
        ctx.check(
            f"After DELETE the {label} policy is no longer custom",
            ctx.json(after).get("is_custom") is False,
            ctx.evidence(after),
        )


def _delete_key(ctx: GroupContext, key_id: str) -> None:
    ch = ctx.json(ctx.api.post(f"/api/keys/{key_id}/delete/challenge"))
    resp = ctx.api.delete(
        f"/api/keys/{key_id}",
        json={"challenge_id": ch.get("challenge_id"), "word": ch.get("word")},
    )
    if resp.status_code not in (200, 204):
        ctx.warn(f"could not delete test API key {key_id}: HTTP {resp.status_code}")
