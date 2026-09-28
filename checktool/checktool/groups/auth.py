"""Group: user registration, password login, session lifecycle."""

from __future__ import annotations

from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    import secrets

    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class AuthGroup(Group):
    slug = "auth"
    title = "User auth & sessions"
    description = "Register a user, log in, read the profile, rotate and revoke sessions."
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("user")
        password = _strong_password()
        user_id: Optional[str] = None

        try:
            resp = ctx.request(
                "A new user registers with email + password",
                "POST",
                "/api/users",
                json={"email": email, "password": password, "first_name": "Check", "last_name": "User"},
            )
            if resp.status_code == 403:
                ctx.skip("Public self-registration is disabled", "falling back to admin create")
                resp = ctx.request(
                    "Admin creates the user instead",
                    "POST",
                    "/api/admin/users/create",
                    json={
                        "email": email,
                        "password": password,
                        "scopes": ["read"],
                        "email_verified": True,
                    },
                )
            ctx.check(
                "The user account is created",
                resp.status_code in (200, 201),
                ctx.evidence(resp),
            )
            user_id = ctx.json(resp).get("id")
            if not user_id:
                return

            # Log in as the new user (browser-style: authorize -> code -> token).
            user_api = ctx.new_client()
            ctx.step("The user logs in with email + password (authorization code + PKCE)",
                     "POST", "/api/oauth2/authorize")
            cfg = user_api.oidc_config()
            bundle = user_api.admin_login(email, password)
            ctx.check(
                "Password login yields an access token",
                bool(bundle.access_token),
                "no access_token in token response",
            )

            me = ctx.request(
                "The profile endpoint returns the signed-in user",
                "GET",
                "/api/users/me",
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            ctx.check(
                "GET /api/users/me returns the new user's email",
                me.status_code == 200 and ctx.json(me).get("email") == email,
                ctx.evidence(me),
            )

            anon = ctx.new_client()
            denied = anon.get("/api/users/me")
            ctx.check(
                "GET /api/users/me without a token is rejected (401)",
                denied.status_code == 401,
                ctx.evidence(denied),
            )

            # Active refresh-token sessions.
            sessions = user_api.get(
                "/api/tokens/refresh/list",
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            total = ctx.json(sessions).get("total")
            ctx.check(
                "The login appears in the user's active sessions",
                sessions.status_code == 200 and isinstance(total, int) and total >= 1,
                ctx.evidence(sessions),
            )

            # Refresh-token rotation.
            if bundle.refresh_token:
                refreshed, rresp = user_api.refresh_token(
                    bundle.refresh_token, cfg.get("client_id", "")
                )
                ctx.check(
                    "Refreshing rotates to a new access + refresh token",
                    refreshed.access_token != bundle.access_token
                    and refreshed.refresh_token not in (None, bundle.refresh_token),
                    ctx.evidence(rresp),
                )
            else:
                ctx.check("Login issued an offline_access refresh token", False, "no refresh_token")

            # Log out everywhere.
            revoked = user_api.post(
                "/api/tokens/refresh/revoke-all",
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            after = user_api.get(
                "/api/tokens/refresh/list",
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            ctx.check(
                "Log out everywhere revokes all sessions",
                revoked.status_code == 200 and ctx.json(after).get("total") == 0,
                ctx.evidence(after),
            )
        finally:
            _cleanup_user(ctx, user_id, email)


def _cleanup_user(ctx: GroupContext, user_id: Optional[str], email: str) -> None:
    if user_id is None:
        resp = ctx.api.get(f"/api/admin/users/search?search={email}")
        items = ctx.json(resp).get("items") if resp.status_code == 200 else None
        if items:
            user_id = items[0].get("id")
    if not user_id:
        return
    resp = ctx.api.delete(f"/api/admin/users/{user_id}")
    if resp.status_code not in (200, 204):
        ctx.warn(f"could not delete test user {email}: HTTP {resp.status_code}")
