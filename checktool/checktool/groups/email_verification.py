"""Group: email verification + resend (uses the demo inbox for the code)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.helpers import newest_email_code
from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class EmailVerificationGroup(Group):
    slug = "email_verification"
    title = "Email verification"
    description = (
        "Create an unverified user, resend the verification email, harvest the code "
        "from the demo inbox and confirm the account becomes verified."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("verify-user")
        password = _strong_password()
        user_id: Optional[str] = None
        try:
            created = ctx.request(
                "An unverified user is created",
                "POST",
                "/api/admin/users/create",
                json={
                    "email": email,
                    "password": password,
                    "scopes": ["read"],
                    "email_verified": False,
                },
            )
            user_id = ctx.json(created).get("id")
            ctx.check(
                "POST /api/admin/users/create creates an unverified user",
                created.status_code == 201 and bool(user_id),
                ctx.evidence(created),
            )
            if not user_id:
                return

            detail = ctx.api.get(f"/api/admin/users/{user_id}")
            ctx.check(
                "The user starts unverified",
                ctx.json(detail).get("email_verified") is False,
                ctx.evidence(detail),
            )

            ctx.step(
                "The verification email is sent again (unauthenticated)",
                "POST",
                "/api/email/resend-verification",
            )
            resend = ctx.new_client().post(
                "/api/email/resend-verification", json={"email": email}
            )
            # A configured-but-undeliverable backend (e.g. EMAIL_BACKEND=resend
            # without a key) makes the endpoint 400 even though the token was
            # created; the demo inbox still receives the code. Treat that as an
            # environment limitation, not a product failure.
            delivery_unavailable = resend.status_code == 400 and "Failed to send" in resend.text
            ctx.check(
                "POST /api/email/resend-verification is accepted",
                resend.status_code == 200 or delivery_unavailable,
                ctx.evidence(resend),
            )
            if delivery_unavailable:
                ctx.warn(
                    "resend accepted the request but the email backend could not deliver it"
                )

            if not _demo_mode(ctx):
                ctx.skip(
                    "Email verification with the harvested code",
                    "demo_mode is false, so GET /api/demo/inbox is unavailable",
                )
                return

            inbox = ctx.request(
                "The demo inbox is read for the verification code",
                "GET",
                f"/api/demo/inbox?email={email}",
            )
            code = newest_email_code(ctx.json(inbox))
            ctx.check(
                "A verification code is captured from the inbox",
                bool(code),
                ctx.evidence(inbox),
            )
            if code:
                ctx.expose("Email verification code", code, note="from the demo inbox")
            if not code:
                return

            verified = ctx.api.post("/api/email/verify", json={"token": code})
            ctx.check(
                "POST /api/email/verify accepts the code",
                verified.status_code == 200,
                ctx.evidence(verified),
            )

            after = ctx.api.get(f"/api/admin/users/{user_id}")
            ctx.check(
                "The user is now email_verified",
                ctx.json(after).get("email_verified") is True,
                ctx.evidence(after),
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")


def _demo_mode(ctx: GroupContext) -> bool:
    return bool(ctx.json(ctx.api.get("/api/meta")).get("demo_mode"))
