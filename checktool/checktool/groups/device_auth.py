"""Group: RFC 8628 device authorization grant end to end."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class DeviceAuthGroup(Group):
    slug = "device_auth"
    title = "Device authorization grant"
    description = (
        "A device requests a code, a user looks it up and approves it, the device "
        "polls a token and the user revokes the authorization."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        user_id: Optional[str] = None
        try:
            client = ctx.request(
                "A device-grant OAuth client is registered",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("device-client"),
                    "redirect_uris": [],
                    "allowed_scopes": ["openid", "profile", "email", "read", "offline_access"],
                    "grant_types": [DEVICE_GRANT],
                    # The device endpoint authenticates the secret via the
                    # form body (client_secret_post), so register that method.
                    "token_endpoint_auth_method": "client_secret_post",
                },
            )
            client_body = ctx.json(client)
            client_id = client_body.get("client_id")
            client_secret = client_body.get("client_secret")
            ctx.check(
                "Admin creates a device-grant client",
                client.status_code == 201 and bool(client_id and client_secret),
                ctx.evidence(client),
            )
            if not client_id or not client_secret:
                return

            user_email = ctx.email("device-user")
            password = _strong_password()
            created_user = ctx.request(
                "A test user is created to approve the device",
                "POST",
                "/api/admin/users/create",
                json={
                    "email": user_email,
                    "password": password,
                    "scopes": ["read"],
                    "email_verified": True,
                },
            )
            user_id = ctx.json(created_user).get("id")
            ctx.check(
                "The approving user exists",
                created_user.status_code == 201 and bool(user_id),
                ctx.evidence(created_user),
            )
            if not user_id:
                return
            user_api = ctx.new_client()
            user_api.admin_login(user_email, password)

            device = ctx.request(
                "The device requests an authorization code",
                "POST",
                "/oauth2/device/authorize",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "scope": "read",
                },
            )
            device_body = ctx.json(device)
            device_code = device_body.get("device_code")
            user_code = device_body.get("user_code")
            ctx.check(
                "POST /oauth2/device/authorize returns device + user codes",
                device.status_code == 200 and bool(device_code and user_code),
                ctx.evidence(device),
            )
            if device_code:
                ctx.expose("Device code", device_code, note="poll /oauth2/token with it")
            if user_code:
                ctx.expose("User code", user_code, note="enter at the verification URI")
            if not device_code or not user_code:
                return

            lookup = user_api.post("/api/oauth2/device/verify", json={"user_code": user_code})
            ctx.check(
                "The user can look up the device code",
                lookup.status_code == 200
                and ctx.json(lookup).get("client_id") == client_id,
                ctx.evidence(lookup),
            )

            approved = user_api.post(
                "/api/oauth2/device/approve", json={"user_code": user_code}
            )
            ctx.check(
                "The user approves the device",
                approved.status_code == 200,
                ctx.evidence(approved),
            )

            token = ctx.api.post(
                "/oauth2/token",
                data={
                    "grant_type": DEVICE_GRANT,
                    "device_code": device_code,
                    "client_id": client_id,
                    "client_secret": client_secret,
                },
            )
            ctx.check(
                "The device polls an access token",
                token.status_code == 200 and bool(ctx.json(token).get("access_token")),
                ctx.evidence(token),
            )

            listed = user_api.get("/api/oauth2/device/authorizations")
            ctx.check(
                "The authorization is listed for the user",
                listed.status_code == 200
                and any(
                    a.get("user_code") == user_code
                    for a in ctx.json(listed).get("device_authorizations", [])
                ),
                ctx.evidence(listed),
            )

            revoked = user_api.post(
                f"/api/oauth2/device/authorizations/{user_code}/revoke"
            )
            ctx.check(
                "The user can revoke the authorization",
                revoked.status_code == 200,
                ctx.evidence(revoked),
            )
        finally:
            if user_id:
                removed_user = ctx.api.delete(f"/api/admin/users/{user_id}")
                if removed_user.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete test user {user_id}: HTTP {removed_user.status_code}"
                    )
            if client_id:
                resp = ctx.api.delete(f"/api/oauth-clients/{client_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete device OAuth client {client_id}: HTTP {resp.status_code}"
                    )
