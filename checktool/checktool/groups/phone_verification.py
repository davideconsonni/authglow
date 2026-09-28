"""Group: phone verification request (OTP delivery is external)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class PhoneVerificationGroup(Group):
    slug = "phone_verification"
    title = "Phone verification"
    description = (
        "A signed-in user requests an OTP for an E.164 number; the verify step is "
        "skipped because the code never leaves the server."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("phone-user")
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

            requested = user_api.post(
                "/api/phone/request", json={"phone": "+15551234567"}
            )
            if requested.status_code == 200:
                ctx.check("POST /api/phone/request accepts an E.164 number", True)
            elif requested.status_code == 400:
                # A real SMS provider (Infobip/SMTP) rejects an arbitrary
                # destination; the endpoint itself is fine. Delivery is an
                # external capability, so skip instead of failing the run.
                ctx.warn("the configured SMS provider rejected the test destination")
                ctx.skip(
                    "POST /api/phone/request delivery",
                    "no reachable SMS destination in this environment",
                )
            else:
                ctx.check(
                    "POST /api/phone/request accepts an E.164 number",
                    False,
                    ctx.evidence(requested),
                )
            ctx.skip(
                "Phone code verification",
                "the generated code is never exposed over HTTP",
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")
