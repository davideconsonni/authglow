"""Group: external IdP federation configuration (admin CRUD, no real IdP)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


@register_group
class FederationGroup(Group):
    slug = "federation"
    title = "Federation providers"
    description = (
        "Register an external IdP, list/update/toggle it, verify public visibility "
        "and delete it."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        provider_id: Optional[str] = None
        try:
            created = ctx.request(
                "An external identity provider is registered",
                "POST",
                "/api/federation/providers",
                json={
                    "label": ctx.name("idp"),
                    "issuer": "https://idp.example.com",
                    "client_id": ctx.name("idp-client"),
                    "client_secret": secrets.token_urlsafe(24),
                    "scopes": ["openid", "profile", "email"],
                },
            )
            body = ctx.json(created)
            provider_id = body.get("id")
            ctx.check(
                "POST /api/federation/providers creates the provider",
                created.status_code in (200, 201) and bool(provider_id),
                ctx.evidence(created),
            )
            ctx.check(
                "The client_secret is never returned",
                "client_secret" not in body,
                str(sorted(body.keys())),
            )
            if provider_id:
                ctx.expose("Federation provider id", provider_id, secret=False)
            if not provider_id:
                return

            admin_list = ctx.api.get("/api/federation/admin/providers")
            admin_ids = _ids(ctx.json(admin_list))
            ctx.check(
                "The provider appears in the admin list",
                admin_list.status_code == 200 and provider_id in admin_ids,
                ctx.evidence(admin_list),
            )

            renamed = ctx.name("idp-renamed")
            updated = ctx.api.put(
                f"/api/federation/admin/providers/{provider_id}", json={"label": renamed}
            )
            ctx.check(
                "PUT /api/federation/admin/providers/{id} updates the label",
                updated.status_code == 200 and ctx.json(updated).get("label") == renamed,
                ctx.evidence(updated),
            )

            public_before = ctx.api.get("/api/federation/providers")
            ctx.check(
                "An enabled provider is listed on the public endpoint",
                public_before.status_code == 200
                and provider_id in _ids(ctx.json(public_before)),
                ctx.evidence(public_before),
            )

            toggled = ctx.api.patch(
                f"/api/federation/admin/providers/{provider_id}/toggle"
            )
            ctx.check(
                "PATCH .../toggle disables the provider",
                toggled.status_code == 200
                and ctx.json(toggled).get("enabled") is False,
                ctx.evidence(toggled),
            )

            public_after = ctx.api.get("/api/federation/providers")
            ctx.check(
                "A disabled provider is hidden from the public endpoint",
                provider_id not in _ids(ctx.json(public_after)),
                ctx.evidence(public_after),
            )

            deleted = ctx.api.delete(f"/api/federation/admin/providers/{provider_id}")
            ctx.check(
                "DELETE /api/federation/admin/providers/{id} removes the provider",
                deleted.status_code in (200, 204),
                ctx.evidence(deleted),
            )
            if deleted.status_code in (200, 204):
                provider_id = None
        finally:
            if provider_id:
                resp = ctx.api.delete(f"/api/federation/admin/providers/{provider_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete test provider {provider_id}: HTTP {resp.status_code}"
                    )


def _ids(body: object) -> list:
    if not isinstance(body, list):
        return []
    return [entry.get("id") for entry in body if isinstance(entry, dict)]
