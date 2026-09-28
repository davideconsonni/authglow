"""Group: RBAC permissions, roles and enforcement."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class RbacGroup(Group):
    slug = "rbac"
    title = "RBAC roles & permissions"
    description = "Create a permission and role, assign it to a user, verify effective access and denial."
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        perm_name = f"{ctx.config.namespace}-things.read"
        role_name = ctx.name("role")
        password = _strong_password()
        user_id: Optional[str] = None
        other_id: Optional[str] = None
        perm_id: Optional[str] = None
        role_id: Optional[str] = None

        try:
            user_id, user_email, other_id, other_email = self._create_users(ctx, password)

            perm = ctx.request(
                "A new permission is defined",
                "POST",
                "/api/rbac/permissions",
                json={"name": perm_name, "description": "checktool permission"},
            )
            perm_id = ctx.json(perm).get("permission_id")
            ctx.check(
                "POST /api/rbac/permissions creates the permission",
                perm.status_code == 201 and bool(perm_id),
                ctx.evidence(perm),
            )

            role = ctx.request(
                "A role bundling that permission is created",
                "POST",
                "/api/rbac/roles",
                json={"name": role_name, "description": "checktool role", "permissions": [perm_name]},
            )
            role_id = ctx.json(role).get("role_id")
            ctx.check(
                "POST /api/rbac/roles creates the role",
                role.status_code == 201 and bool(role_id),
                ctx.evidence(role),
            )
            if not (user_id and other_id and perm_id and role_id):
                return

            assign = ctx.request(
                "The role is assigned to the user",
                "POST",
                "/api/rbac/user-roles",
                json={"user_id": user_id, "role_id": role_id},
            )
            ctx.check(
                "POST /api/rbac/user-roles assigns the role",
                assign.status_code == 201,
                ctx.evidence(assign),
            )

            effective = ctx.api.get(f"/api/rbac/users/{user_id}/permissions")
            eff = ctx.json(effective)
            ctx.check(
                "The user's effective permissions include the new permission",
                effective.status_code == 200
                and perm_name in (eff.get("permissions") or [])
                and role_name in (eff.get("roles") or []),
                ctx.evidence(effective),
            )

            other = ctx.api.get(f"/api/rbac/users/{other_id}/permissions")
            ctx.check(
                "A user without the role does NOT get the permission",
                other.status_code == 200
                and perm_name not in (ctx.json(other).get("permissions") or []),
                ctx.evidence(other),
            )

            # Enforcement: holding a custom role does not grant admin authority.
            user_api = ctx.new_client()
            bundle = user_api.admin_login(user_email, password)
            denied = user_api.post(
                "/api/rbac/roles",
                json={"name": ctx.name("should-not-exist")},
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            ctx.check(
                "A non-admin role cannot manage roles (403)",
                denied.status_code == 403,
                ctx.evidence(denied),
            )
        finally:
            _cleanup(ctx, user_id, other_id, role_id, perm_id)

    def _create_users(self, ctx: GroupContext, password: str) -> tuple:
        user_email = ctx.email("rbac-user")
        other_email = ctx.email("rbac-other")
        first = ctx.api.post(
            "/api/admin/users/create",
            json={
                "email": user_email,
                "password": password,
                "scopes": ["read"],
                "email_verified": True,
            },
        )
        second = ctx.api.post(
            "/api/admin/users/create",
            json={
                "email": other_email,
                "password": password,
                "scopes": ["read"],
                "email_verified": True,
            },
        )
        first_id = ctx.json(first).get("id")
        second_id = ctx.json(second).get("id")
        ctx.check(
            "Two test users are created (one to grant, one as control)",
            bool(first_id and second_id),
            ctx.evidence(first if not first_id else second),
        )
        return first_id, user_email, second_id, other_email


def _cleanup(
    ctx: GroupContext,
    user_id: Optional[str],
    other_id: Optional[str],
    role_id: Optional[str],
    perm_id: Optional[str],
) -> None:
    if user_id and role_id:
        ctx.api.delete(f"/api/rbac/user-roles/{user_id}/{role_id}")
    if role_id:
        ctx.api.delete(f"/api/rbac/roles/{role_id}")
    if perm_id:
        ctx.api.delete(f"/api/rbac/permissions/{perm_id}")
    for uid in (user_id, other_id):
        if uid:
            resp = ctx.api.delete(f"/api/admin/users/{uid}")
            if resp.status_code not in (200, 204):
                ctx.warn(f"could not delete test user {uid}: HTTP {resp.status_code}")
