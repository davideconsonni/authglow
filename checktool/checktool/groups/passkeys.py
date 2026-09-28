"""Group: passkey/WebAuthn local surface (ceremonies need a real authenticator)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class PasskeysGroup(Group):
    slug = "passkeys"
    title = "Passkeys (WebAuthn)"
    description = (
        "List a user's passkeys (empty is fine) and read the admin count; registration "
        "and authentication ceremonies need a browser/authenticator."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("passkey-user")
        password = _strong_password()
        user_id: Optional[str] = None
        try:
            created = ctx.request(
                "A test user is created",
                "POST",
                "/api/admin/users/create",
                json={
                    "email": email,
                    "password": password,
                    "scopes": ["read"],
                    "email_verified": True,
                },
            )
            user_id = ctx.json(created).get("id")
            ctx.check(
                "POST /api/admin/users/create creates the user",
                created.status_code == 201 and bool(user_id),
                ctx.evidence(created),
            )
            if not user_id:
                return

            user_api = ctx.new_client()
            user_api.admin_login(email, password)

            own = user_api.get("/api/passkey/list")
            ctx.check(
                "GET /api/passkey/list returns the user's passkeys",
                own.status_code == 200 and isinstance(ctx.json(own), list),
                ctx.evidence(own),
            )

            admin = ctx.api.get(f"/api/admin/users/{user_id}/passkeys")
            ctx.check(
                "GET /api/admin/users/{id}/passkeys returns a count",
                admin.status_code == 200
                and isinstance(ctx.json(admin).get("count"), int),
                ctx.evidence(admin),
            )

            ctx.skip(
                "Passkey registration ceremony",
                "WebAuthn registration requires a browser/authenticator",
            )
            ctx.skip(
                "Passkey authentication ceremony",
                "WebAuthn assertion requires a browser/authenticator",
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")
