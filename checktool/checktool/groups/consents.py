"""Group: OAuth2 consent record lifecycle (grant then admin-revoke)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.client import pkce_pair
from checktool.registry import Group, GroupContext, register_group

REDIRECT_URI = "http://localhost:9999/callback"
SCOPE = "openid profile email read offline_access"


@register_group
class ConsentsGroup(Group):
    slug = "consents"
    title = "OAuth consents"
    description = (
        "Drive a consent-requiring authorization so a consent is recorded, find it "
        "in the admin list and revoke it."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        try:
            created = ctx.request(
                "A consent-requiring client is created",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("consent-client"),
                    "redirect_uris": [REDIRECT_URI],
                    "allowed_scopes": SCOPE.split(),
                    "grant_types": ["authorization_code", "refresh_token"],
                    "require_consent": True,
                },
            )
            client_id = ctx.json(created).get("client_id")
            ctx.check(
                "The consent client exists",
                created.status_code == 201 and bool(client_id),
                ctx.evidence(created),
            )
            if not client_id:
                return

            _, challenge = pkce_pair()
            user_api = ctx.new_client()
            authorized = user_api.post(
                "/api/oauth2/authorize",
                data={
                    "email": ctx.admin_email or "",
                    "password": ctx.admin_password or "",
                    "client_id": client_id,
                    "redirect_uri": REDIRECT_URI,
                    "response_type": "code",
                    "scope": SCOPE,
                    "state": secrets.token_urlsafe(32),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
            )
            authorized_body = ctx.json(authorized)
            session_token = authorized_body.get("session_token")
            ctx.check(
                "Authorize asks for consent before issuing a code",
                authorized.status_code == 200
                and authorized_body.get("consent_required") is True
                and bool(session_token),
                ctx.evidence(authorized),
            )
            if session_token:
                ctx.expose(
                    "Consent session token",
                    session_token,
                    note="pass to /oauth2/consent",
                    api=user_api,
                )
            if not session_token:
                return

            granted = user_api.post(
                "/oauth2/consent",
                data={
                    "session_token": session_token,
                    "approved": "true",
                    "remember": "true",
                },
            )
            ctx.check(
                "Consent is granted and an authorization code is issued",
                granted.status_code == 200
                and bool(ctx.json(granted).get("authorization_code")),
                ctx.evidence(granted),
            )

            listing = ctx.api.get(
                f"/api/admin/oauth-consents?email={ctx.admin_email or ''}"
            )
            consent_item = _find_consent(ctx.json(listing), client_id)
            ctx.check(
                "The consent appears (unrevoked) in the admin list",
                listing.status_code == 200
                and consent_item is not None
                and consent_item.get("revoked") is False,
                ctx.evidence(listing),
            )
            if not consent_item:
                return

            revoked = ctx.api.post(
                f"/api/admin/oauth-consents/{consent_item.get('consent_id')}/revoke"
            )
            ctx.check(
                "POST /api/admin/oauth-consents/{id}/revoke succeeds",
                revoked.status_code == 200,
                ctx.evidence(revoked),
            )

            after = ctx.api.get(
                f"/api/admin/oauth-consents?email={ctx.admin_email or ''}"
            )
            after_consent = _find_consent(ctx.json(after), client_id)
            ctx.check(
                "The consent is marked revoked in the admin list",
                after_consent is not None and after_consent.get("revoked") is True,
                ctx.evidence(after),
            )
        finally:
            if client_id:
                resp = ctx.api.delete(f"/api/oauth-clients/{client_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete consent client {client_id}: HTTP {resp.status_code}"
                    )


def _find_consent(body: object, client_id: str) -> Optional[dict]:
    items = body.get("items") if isinstance(body, dict) else None
    if not isinstance(items, list):
        return None
    for item in items:
        if isinstance(item, dict) and item.get("client_id") == client_id:
            return item
    return None
