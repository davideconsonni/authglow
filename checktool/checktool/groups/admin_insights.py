"""Group: admin forensic / read-only insight endpoints."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class AdminInsightsGroup(Group):
    slug = "admin_insights"
    title = "Admin insights"
    description = (
        "Login history, security events, per-user consents, admin actions, GDPR "
        "export and passkey count for a user with a real login."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("insights-user")
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

            login = ctx.new_client().admin_login(email, password)
            ctx.check("The user logs in (seeds the audit trail)", bool(login.access_token))

            history = ctx.api.get(f"/api/admin/users/{user_id}/login-history")
            ctx.check(
                "GET .../login-history returns paginated entries",
                history.status_code == 200
                and isinstance(ctx.json(history).get("items"), list),
                ctx.evidence(history),
            )

            security = ctx.api.get(f"/api/admin/users/{user_id}/security-events")
            ctx.check(
                "GET .../security-events returns a paginated envelope",
                security.status_code == 200
                and isinstance(ctx.json(security).get("items"), list),
                ctx.evidence(security),
            )

            consents = ctx.api.get(f"/api/admin/users/{user_id}/oauth-consents")
            ctx.check(
                "GET .../oauth-consents returns a list",
                consents.status_code == 200 and isinstance(ctx.json(consents), list),
                ctx.evidence(consents),
            )

            actions = ctx.api.get(f"/api/admin/users/{user_id}/admin-actions")
            ctx.check(
                "GET .../admin-actions returns a paginated envelope",
                actions.status_code == 200
                and isinstance(ctx.json(actions).get("items"), list),
                ctx.evidence(actions),
            )

            exported = ctx.api.get(f"/api/admin/users/{user_id}/export")
            ctx.check(
                "GET .../export returns the user dossier",
                exported.status_code == 200
                and isinstance(ctx.json(exported).get("user"), dict),
                ctx.evidence(exported),
            )

            passkeys = ctx.api.get(f"/api/admin/users/{user_id}/passkeys")
            ctx.check(
                "GET .../passkeys returns a count",
                passkeys.status_code == 200
                and isinstance(ctx.json(passkeys).get("count"), int),
                ctx.evidence(passkeys),
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")
