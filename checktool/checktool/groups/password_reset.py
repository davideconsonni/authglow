"""Group: password reset + forced (expired) password change."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.helpers import newest_email_code
from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class PasswordResetGroup(Group):
    slug = "password_reset"
    title = "Password reset"
    description = (
        "Request a reset, confirm it with the demo-inbox code, then complete an "
        "admin-forced password change."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("reset-user")
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

            requested = ctx.request(
                "A password reset is requested",
                "POST",
                "/api/password/reset/request",
                json={"email": email},
            )
            ctx.check(
                "POST /api/password/reset/request returns 200",
                requested.status_code == 200,
                ctx.evidence(requested),
            )

            if _demo_mode(ctx):
                inbox = ctx.request(
                    "The reset code is read from the demo inbox",
                    "GET",
                    f"/api/demo/inbox?email={email}",
                )
                code = newest_email_code(ctx.json(inbox))
                ctx.check(
                    "A reset code is captured from the inbox",
                    bool(code),
                    ctx.evidence(inbox),
                )
                if code:
                    ctx.expose("Password reset code", code, note="from the demo inbox")
                if code:
                    new_password = _strong_password()
                    confirmed = ctx.api.post(
                        "/api/password/reset/confirm",
                        json={"reset_code": code, "new_password": new_password},
                    )
                    ctx.check(
                        "POST /api/password/reset/confirm succeeds",
                        confirmed.status_code == 200,
                        ctx.evidence(confirmed),
                    )
                    login = ctx.new_client().admin_login(email, new_password)
                    ctx.check(
                        "Login with the reset password succeeds",
                        bool(login.access_token),
                        "no access_token",
                    )
                    password = new_password
            else:
                ctx.skip(
                    "Password reset confirmation",
                    "demo_mode is false, so GET /api/demo/inbox is unavailable",
                )

            # --- forced change --------------------------------------------
            expired = ctx.api.post(f"/api/admin/users/{user_id}/expire-password")
            ctx.check(
                "An admin can expire the password",
                expired.status_code == 200,
                ctx.evidence(expired),
            )

            client = ctx.new_client()
            cfg = client.oidc_config()
            challenged = client.authorize_code(
                email=email,
                password=password,
                client_id=cfg.get("client_id", ""),
                redirect_uri=cfg.get("redirect_uri", ""),
            )
            ctx.check(
                "Login now reports password_expired",
                challenged.get("password_expired") is True,
                str(challenged),
            )

            final_password = _strong_password()
            changed = ctx.api.post(
                "/api/auth/expired-password/change",
                json={
                    "email": email,
                    "current_password": password,
                    "new_password": final_password,
                },
            )
            ctx.check(
                "POST /api/auth/expired-password/change succeeds",
                changed.status_code == 200,
                ctx.evidence(changed),
            )

            login = ctx.new_client().admin_login(email, final_password)
            ctx.check(
                "Login with the forced-change password succeeds",
                bool(login.access_token),
                "no access_token",
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")


def _demo_mode(ctx: GroupContext) -> bool:
    return bool(ctx.json(ctx.api.get("/api/meta")).get("demo_mode"))
