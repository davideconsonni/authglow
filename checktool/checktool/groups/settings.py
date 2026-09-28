"""Group: runtime settings + rate-limit administration (non-destructive)."""

from __future__ import annotations

from typing import Any, Dict, Optional

from checktool.registry import Group, GroupContext, register_group

OVERRIDE_PATH = "/api/admin/settings"


@register_group
class SettingsGroup(Group):
    slug = "settings"
    title = "Runtime settings"
    description = (
        "Read the settings list and schema, round-trip a no-op override, inspect the "
        "rate-limit table and set/restore a per-route override."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        listing = ctx.request("The admin settings are listed", "GET", "/api/admin/settings")
        fields = ctx.json(listing).get("settings")
        ctx.check(
            "GET /api/admin/settings returns settings",
            listing.status_code == 200
            and isinstance(fields, list)
            and bool(fields),
            ctx.evidence(listing),
        )

        schema = ctx.request(
            "The settings schema is available", "GET", "/api/admin/settings/schema"
        )
        ctx.check(
            "GET /api/admin/settings/schema returns a schema",
            schema.status_code == 200
            and bool(ctx.json(schema).get("settings_by_category")),
            ctx.evidence(schema),
        )

        target = _pick_field(fields)
        if target is None:
            ctx.skip(
                "No-op settings update",
                "no untouched, non-restart boolean setting available",
            )
        else:
            patched = ctx.api.patch(
                "/api/admin/settings", json={target["key"]: target["value"]}
            )
            ctx.check(
                "PATCH /api/admin/settings accepts a no-op update",
                patched.status_code == 200
                and target["key"] in (ctx.json(patched).get("updated") or []),
                ctx.evidence(patched),
            )
            restored = ctx.api.patch("/api/admin/settings", json={target["key"]: None})
            if restored.status_code != 200:
                ctx.warn("could not remove the no-op settings override")

        rate_limits = ctx.request(
            "The rate-limit table is listed", "GET", "/api/admin/rate-limits"
        )
        ctx.check(
            "GET /api/admin/rate-limits returns the route table",
            rate_limits.status_code == 200
            and isinstance(ctx.json(rate_limits).get("rate_limits"), list),
            ctx.evidence(rate_limits),
        )

        status = ctx.request(
            "The rate-limit status is read", "GET", "/api/admin/rate-limits/status"
        )
        ctx.check(
            "GET /api/admin/rate-limits/status reports the global flag",
            status.status_code == 200 and "enabled" in ctx.json(status),
            ctx.evidence(status),
        )

        try:
            applied = ctx.api.put(
                "/api/admin/rate-limits/config",
                json={"overrides": {OVERRIDE_PATH: "1000/minute"}},
            )
            ctx.check(
                "PUT /api/admin/rate-limits/config sets a per-route override",
                applied.status_code == 200
                and (ctx.json(applied).get("overrides") or {}).get(OVERRIDE_PATH)
                == "1000/minute",
                ctx.evidence(applied),
            )
        finally:
            ctx.api.put(
                "/api/admin/rate-limits/config",
                json={"overrides": {OVERRIDE_PATH: None}},
            )


def _pick_field(fields: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(fields, list):
        return None
    for field in fields:
        if not isinstance(field, dict):
            continue
        if (
            field.get("type") == "boolean"
            and field.get("editable") is True
            and field.get("overridden") is False
            and field.get("restart_required") is False
            and isinstance(field.get("value"), bool)
        ):
            return field
    return None
