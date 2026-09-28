"""Group: MFA (TOTP) lifecycle — enroll, verify, challenge login, recovery, disable."""

from __future__ import annotations

import secrets
from typing import Optional

import pyotp

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


def _totp(secret: str) -> str:
    # Fresh code right before each verification (time-based).
    return pyotp.TOTP(secret).now()


@register_group
class MfaGroup(Group):
    slug = "mfa"
    title = "MFA (TOTP)"
    description = (
        "Enroll a user in TOTP MFA, verify it, complete an MFA login challenge, "
        "use a backup code and disable MFA."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        email = ctx.email("mfa-user")
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

            enroll = user_api.post("/api/mfa/enroll")
            enrolled = ctx.json(enroll)
            secret = enrolled.get("secret")
            backup_codes = enrolled.get("backup_codes") or []
            ctx.check(
                "POST /api/mfa/enroll returns a secret and backup codes",
                enroll.status_code == 200
                and bool(secret)
                and len(backup_codes) >= 1,
                ctx.evidence(enroll),
            )
            if secret:
                ctx.expose(
                    "TOTP secret", secret, note="add to an authenticator app", api=user_api
                )
            if backup_codes:
                ctx.expose(
                    "MFA backup codes",
                    ", ".join(backup_codes),
                    note="recovery codes",
                    api=user_api,
                )
            if not secret:
                return

            verified = user_api.post("/api/mfa/verify", json={"code": _totp(secret)})
            ctx.check(
                "POST /api/mfa/verify activates MFA",
                verified.status_code == 200,
                ctx.evidence(verified),
            )

            status = user_api.get("/api/mfa/status")
            status_body = ctx.json(status)
            ctx.check(
                "GET /api/mfa/status reports enabled and verified",
                status.status_code == 200
                and status_body.get("enabled") is True
                and status_body.get("verified") is True,
                ctx.evidence(status),
            )
            ctx.check(
                "Backup codes remain available",
                status_body.get("backup_codes_remaining", 0) >= 1,
                str(status_body),
            )

            # --- MFA challenge during an OAuth login ----------------------
            cfg = user_api.oidc_config()
            client_id = cfg.get("client_id", "")
            redirect_uri = cfg.get("redirect_uri", "")

            login_api = ctx.new_client()
            challenge = login_api.authorize_code(
                email=email,
                password=password,
                client_id=client_id,
                redirect_uri=redirect_uri,
            )
            session_token = challenge.get("session_token")
            ctx.check(
                "Login returns an MFA challenge",
                challenge.get("mfa_required") is True and bool(session_token),
                str(challenge),
            )
            if session_token:
                ctx.expose(
                    "MFA session token",
                    session_token,
                    note="pass to /oauth2/mfa-verify",
                    api=login_api,
                )
            if session_token:
                complete = login_api.post(
                    "/oauth2/mfa-verify",
                    data={"session_token": session_token, "code": _totp(secret)},
                )
                completed = ctx.json(complete)
                code = completed.get("authorization_code")
                ctx.check(
                    "POST /oauth2/mfa-verify completes the MFA login",
                    complete.status_code == 200 and bool(code),
                    ctx.evidence(complete),
                )
                if code:
                    bundle, token_resp = login_api.exchange_code(
                        code=code,
                        verifier=challenge["verifier"],
                        client_id=client_id,
                        redirect_uri=redirect_uri,
                    )
                    ctx.check(
                        "The MFA login yields an access token",
                        bool(bundle.access_token),
                        ctx.evidence(token_resp),
                    )

            # --- backup-code recovery -------------------------------------
            if backup_codes:
                recovery_api = ctx.new_client()
                recovery_challenge = recovery_api.authorize_code(
                    email=email,
                    password=password,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                )
                recovery_token = recovery_challenge.get("session_token")
                recovered = (
                    recovery_api.post(
                        "/oauth2/mfa-verify",
                        data={
                            "session_token": recovery_token,
                            "code": backup_codes[0],
                        },
                    )
                    if recovery_token
                    else None
                )
                ctx.check(
                    "A backup code completes the MFA login",
                    recovered is not None
                    and recovered.status_code == 200
                    and bool(ctx.json(recovered).get("authorization_code")),
                    ctx.evidence(recovered) if recovered is not None else "no session token",
                )

            regenerated = user_api.post("/api/mfa/regenerate-backup-codes")
            new_codes = ctx.json(regenerated).get("backup_codes") or []
            ctx.check(
                "POST /api/mfa/regenerate-backup-codes issues new codes",
                regenerated.status_code == 200 and len(new_codes) >= 1,
                ctx.evidence(regenerated),
            )
            if new_codes:
                ctx.expose("Regenerated backup codes", ", ".join(new_codes), api=user_api)

            disabled = user_api.delete("/api/mfa/disable")
            ctx.check(
                "DELETE /api/mfa/disable turns MFA off",
                disabled.status_code == 200,
                ctx.evidence(disabled),
            )
            after = ctx.json(user_api.get("/api/mfa/status"))
            ctx.check(
                "MFA status is disabled afterwards",
                after.get("enabled") is False and after.get("verified") is False,
                str(after),
            )
        finally:
            if user_id:
                resp = ctx.api.delete(f"/api/admin/users/{user_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test user {user_id}: HTTP {resp.status_code}")
