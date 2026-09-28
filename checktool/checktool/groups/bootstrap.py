"""Group: public environment and bootstrap surface (no admin required)."""

from __future__ import annotations

from checktool.registry import Group, GroupContext, register_group


@register_group
class BootstrapGroup(Group):
    slug = "bootstrap"
    title = "Environment & bootstrap"
    description = "Health, setup state, public metadata, CSRF token and scopes."
    requires_admin = False

    def run(self, ctx: GroupContext) -> None:
        resp = ctx.request("The server answers the health probe", "GET", "/health")
        body = ctx.json(resp)
        ctx.check(
            "GET /health returns 200 with a healthy status",
            resp.status_code == 200 and body.get("status") in ("healthy", "ok"),
            ctx.evidence(resp),
        )

        resp = ctx.request("Setup completion can be queried", "GET", "/api/setup/check")
        body = ctx.json(resp)
        ctx.check(
            "GET /api/setup/check returns a needs_setup flag",
            resp.status_code == 200 and isinstance(body.get("needs_setup"), bool),
            ctx.evidence(resp),
        )

        resp = ctx.request("Public metadata (demo banner) is exposed", "GET", "/api/meta")
        body = ctx.json(resp)
        ctx.check(
            "GET /api/meta returns a demo_mode flag",
            resp.status_code == 200 and isinstance(body.get("demo_mode"), bool),
            ctx.evidence(resp),
        )

        resp = ctx.request(
            "A browser client can fetch a CSRF token", "GET", "/api/oauth2/csrf-token"
        )
        body = ctx.json(resp)
        ctx.check(
            "GET /api/oauth2/csrf-token returns a non-empty token",
            resp.status_code == 200 and bool(body.get("csrf_token")),
            ctx.evidence(resp),
        )

        resp = ctx.request("The OAuth scope catalog is public", "GET", "/api/scopes")
        ctx.check("GET /api/scopes returns 200", resp.status_code == 200, ctx.evidence(resp))
