"""Group: demo-only sandbox affordances (skips entirely outside demo mode)."""

from __future__ import annotations

from checktool.registry import Group, GroupContext, register_group


@register_group
class DemoInboxGroup(Group):
    slug = "demo_inbox"
    title = "Demo inbox"
    description = (
        "On a demo instance, read GET /api/meta demo credentials and fetch the demo "
        "mailbox; skipped when demo_mode is false."
    )
    requires_admin = False

    def run(self, ctx: GroupContext) -> None:
        meta = ctx.request("The public instance metadata is read", "GET", "/api/meta")
        meta_body = ctx.json(meta)
        if not meta_body.get("demo_mode"):
            ctx.skip("Demo inbox", "demo_mode is false on this instance")
            return

        ctx.check(
            "GET /api/meta exposes the demo credentials",
            meta.status_code == 200
            and bool(meta_body.get("demo_user_email"))
            and bool(meta_body.get("demo_user_password")),
            ctx.evidence(meta),
        )

        email = meta_body.get("demo_user_email", "")
        inbox = ctx.request(
            "The demo mailbox is read",
            "GET",
            f"/api/demo/inbox?email={email}",
        )
        ctx.check(
            "GET /api/demo/inbox returns the mailbox shape",
            inbox.status_code == 200
            and isinstance(ctx.json(inbox).get("emails"), list),
            ctx.evidence(inbox),
        )
