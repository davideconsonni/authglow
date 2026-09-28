"""Group: admin user management lifecycle."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class AdminUsersGroup(Group):
    slug = "admin_users"
    title = "Admin user management"
    description = "Stats, create, read, update, search, set password, suspend/unsuspend and delete a user."
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("admin-user")
        password = _strong_password()
        user_id: Optional[str] = None
        try:
            stats = ctx.request("The dashboard statistics load", "GET", "/api/admin/stats")
            body = ctx.json(stats)
            ctx.check(
                "GET /api/admin/stats returns user counts",
                stats.status_code == 200 and isinstance(body.get("total_users"), int),
                ctx.evidence(stats),
            )

            created = ctx.request(
                "An admin creates a user with a password",
                "POST",
                "/api/admin/users/create",
                json={
                    "email": email,
                    "password": password,
                    "scopes": ["read"],
                    "email_verified": True,
                    "first_name": "Created",
                },
            )
            user_id = ctx.json(created).get("id")
            ctx.check(
                "POST /api/admin/users/create returns the new user",
                created.status_code == 201 and bool(user_id),
                ctx.evidence(created),
            )
            if not user_id:
                return

            detail = ctx.api.get(f"/api/admin/users/{user_id}")
            ctx.check(
                "GET /api/admin/users/{id} returns the created user",
                detail.status_code == 200 and ctx.json(detail).get("email") == email,
                ctx.evidence(detail),
            )

            updated = ctx.api.put(f"/api/admin/users/{user_id}", json={"first_name": "Renamed"})
            ctx.check(
                "PUT /api/admin/users/{id} updates the user",
                updated.status_code == 200 and ctx.json(updated).get("first_name") == "Renamed",
                ctx.evidence(updated),
            )

            found = ctx.api.get(f"/api/admin/users?search={email}")
            items = _items(ctx.json(found))
            ctx.check(
                "The user can be found via admin search",
                found.status_code == 200 and any(u.get("id") == user_id for u in items),
                ctx.evidence(found),
            )

            reset = ctx.api.post(
                f"/api/admin/users/{user_id}/set-password",
                json={"password": _strong_password(), "require_change": False},
            )
            ctx.check(
                "An admin can set a new password",
                reset.status_code == 200,
                ctx.evidence(reset),
            )

            suspend = ctx.api.post(
                f"/api/admin/users/{user_id}/suspend", json={"duration_hours": 1}
            )
            unsuspend = ctx.api.post(f"/api/admin/users/{user_id}/unsuspend")
            ctx.check(
                "The user can be suspended and unsuspended",
                suspend.status_code == 200 and unsuspend.status_code == 200,
                ctx.evidence(suspend if suspend.status_code != 200 else unsuspend),
            )

            deleted = ctx.api.delete(f"/api/admin/users/{user_id}")
            gone = ctx.api.get(f"/api/admin/users/{user_id}")
            ctx.check(
                "Deleting the user removes it (subsequent read is 404)",
                deleted.status_code in (200, 204) and gone.status_code == 404,
                ctx.evidence(gone),
            )
            if deleted.status_code in (200, 204):
                user_id = None
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")


def _items(body: object) -> list:
    if isinstance(body, dict):
        return body.get("items") or []
    if isinstance(body, list):
        return body
    return []
