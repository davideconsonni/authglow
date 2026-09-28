"""Group: admin session / refresh-token management."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.client import ApiClient, TokenBundle
from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class SessionsGroup(Group):
    slug = "sessions"
    title = "Admin sessions"
    description = (
        "List active sessions, revoke one refresh token, revoke all of a user's "
        "sessions and run the cleanup sweep."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("sessions-user")
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

            first = ctx.new_client()
            first_bundle = first.admin_login(email, password)
            client_id = first.oidc_config().get("client_id", "")

            all_sessions = ctx.api.get(f"/api/admin/sessions?email={email}")
            entries = ctx.json(all_sessions).get("sessions") or []
            ctx.check(
                "GET /api/admin/sessions includes the user's session",
                all_sessions.status_code == 200
                and any(s.get("user_email") == email for s in entries),
                ctx.evidence(all_sessions),
            )

            user_sessions = ctx.api.get(f"/api/admin/users/{user_id}/sessions")
            items = ctx.json(user_sessions).get("items") or []
            token_id = items[0].get("id") if items else None
            ctx.check(
                "GET /api/admin/users/{id}/sessions lists the active session",
                user_sessions.status_code == 200 and bool(token_id),
                ctx.evidence(user_sessions),
            )
            if token_id:
                ctx.expose("Refresh token id", token_id, secret=False, note="revocable via admin")

            if token_id:
                revoked = ctx.api.post(f"/api/admin/tokens/refresh/{token_id}/revoke")
                ctx.check(
                    "POST /api/admin/tokens/refresh/{id}/revoke succeeds",
                    revoked.status_code == 200,
                    ctx.evidence(revoked),
                )
                ctx.check(
                    "The individually revoked refresh token stops working",
                    _refresh_fails(first, first_bundle, client_id),
                    "refresh unexpectedly succeeded",
                )

            second = ctx.new_client()
            second_bundle = second.admin_login(email, password)
            revoke_all = ctx.api.post(f"/api/admin/users/{user_id}/sessions/revoke-all")
            ctx.check(
                "POST /api/admin/users/{id}/sessions/revoke-all succeeds",
                revoke_all.status_code == 200,
                ctx.evidence(revoke_all),
            )
            ctx.check(
                "After revoke-all the user's refresh token stops working",
                _refresh_fails(second, second_bundle, client_id),
                "refresh unexpectedly succeeded",
            )

            cleanup = ctx.api.post("/api/admin/sessions/cleanup")
            ctx.check(
                "POST /api/admin/sessions/cleanup reports a count",
                cleanup.status_code == 200
                and isinstance(ctx.json(cleanup).get("deleted"), int),
                ctx.evidence(cleanup),
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")


def _refresh_fails(client: ApiClient, bundle: TokenBundle, client_id: str) -> bool:
    if not bundle.refresh_token:
        return False
    refreshed, resp = client.refresh_token(bundle.refresh_token, client_id)
    return resp.status_code != 200 or not refreshed.access_token
