"""Group: webhook endpoint CRUD + a real (expected-to-fail) test delivery."""

from __future__ import annotations

from typing import Optional

from checktool.registry import Group, GroupContext, register_group

# Port 9 (discard) on loopback is used as a deliberately unreachable receiver:
# the test delivery must fail without failing the group.
RECEIVER_URL = "http://127.0.0.1:9/hook"


@register_group
class WebhooksGroup(Group):
    slug = "webhooks"
    title = "Webhooks"
    description = (
        "Register an endpoint, list/read/patch it, rotate the signing secret, send a "
        "test event, inspect deliveries and delete it."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        webhook_id: Optional[str] = None
        try:
            created = ctx.request(
                "A webhook endpoint is registered",
                "POST",
                "/api/admin/webhooks",
                json={"url": RECEIVER_URL, "events": ["webhook.test"], "insecure": True},
            )
            body = ctx.json(created)
            webhook_id = body.get("id")
            ctx.check(
                "POST /api/admin/webhooks returns the signing secret once",
                created.status_code == 201
                and bool(webhook_id)
                and bool(body.get("secret")),
                ctx.evidence(created),
            )
            if body.get("secret"):
                ctx.expose("Webhook signing secret", body["secret"], note="plaintext, shown once")
            if not webhook_id:
                return

            listing = ctx.api.get("/api/admin/webhooks")
            ctx.check(
                "GET /api/admin/webhooks lists the endpoint",
                listing.status_code == 200
                and isinstance(ctx.json(listing), list)
                and any(w.get("id") == webhook_id for w in ctx.json(listing)),
                ctx.evidence(listing),
            )

            detail = ctx.api.get(f"/api/admin/webhooks/{webhook_id}")
            detail_body = ctx.json(detail)
            ctx.check(
                "GET /api/admin/webhooks/{id} masks the secret",
                detail.status_code == 200
                and "secret" not in detail_body
                and bool(detail_body.get("masked_secret")),
                ctx.evidence(detail),
            )

            patched = ctx.api.patch(
                f"/api/admin/webhooks/{webhook_id}", json={"active": False}
            )
            ctx.check(
                "PATCH /api/admin/webhooks/{id} deactivates the endpoint",
                patched.status_code == 200
                and ctx.json(patched).get("active") is False,
                ctx.evidence(patched),
            )

            rotated = ctx.api.post(f"/api/admin/webhooks/{webhook_id}/rotate-secret")
            rotated_secret = ctx.json(rotated).get("secret")
            ctx.check(
                "POST .../rotate-secret issues a new secret",
                rotated.status_code == 200 and bool(rotated_secret),
                ctx.evidence(rotated),
            )
            if rotated_secret:
                ctx.expose("Rotated webhook secret", rotated_secret, note="plaintext, shown once")

            tested = ctx.api.post(f"/api/admin/webhooks/{webhook_id}/test")
            ctx.check(
                "POST .../test runs a test delivery and returns its summary",
                tested.status_code == 200,
                ctx.evidence(tested),
            )

            deliveries = ctx.api.get(f"/api/admin/webhooks/{webhook_id}/deliveries")
            delivery_list = ctx.json(deliveries)
            ctx.check(
                "GET .../deliveries records the attempt(s)",
                deliveries.status_code == 200
                and isinstance(delivery_list, list)
                and len(delivery_list) >= 1,
                ctx.evidence(deliveries),
            )
            if isinstance(delivery_list, list) and delivery_list:
                if all(d.get("ok") is False for d in delivery_list):
                    ctx.warn(
                        "the test delivery failed as expected (unreachable loopback receiver)"
                    )

            deleted = ctx.api.delete(f"/api/admin/webhooks/{webhook_id}")
            ctx.check(
                "DELETE /api/admin/webhooks/{id} returns 204",
                deleted.status_code == 204,
                ctx.evidence(deleted),
            )
            if deleted.status_code == 204:
                webhook_id = None
        finally:
            if webhook_id:
                resp = ctx.api.delete(f"/api/admin/webhooks/{webhook_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete test webhook {webhook_id}: HTTP {resp.status_code}"
                    )
