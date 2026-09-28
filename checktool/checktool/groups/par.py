"""Group: Pushed Authorization Requests (RFC 9126)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.client import parse_redirect_params, pkce_pair
from checktool.registry import Group, GroupContext, register_group

REDIRECT_URI = "http://localhost:9999/callback"
SCOPE = "openid profile email read offline_access"


@register_group
class ParGroup(Group):
    slug = "par"
    title = "Pushed Authorization Requests"
    description = (
        "Push an authorization request, consume its request_uri at /authorize, "
        "exchange the code and prove the request_uri is single-use."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        try:
            created = ctx.request(
                "A client is created for PAR",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("par-client"),
                    "redirect_uris": [REDIRECT_URI],
                    "allowed_scopes": SCOPE.split(),
                    "grant_types": ["authorization_code", "refresh_token"],
                    "require_consent": False,
                },
            )
            body = ctx.json(created)
            client_id = body.get("client_id")
            client_secret = body.get("client_secret")
            ctx.check(
                "The PAR client exists",
                created.status_code == 201 and bool(client_id and client_secret),
                ctx.evidence(created),
            )
            if not client_id or not client_secret:
                return
            basic = (client_id, client_secret)

            verifier, challenge = pkce_pair()
            state = secrets.token_urlsafe(32)
            pushed = ctx.request(
                "The client pushes its authorization request",
                "POST",
                "/oauth2/par",
                data={
                    "client_id": client_id,
                    "response_type": "code",
                    "redirect_uri": REDIRECT_URI,
                    "scope": SCOPE,
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                auth=basic,
            )
            pushed_body = ctx.json(pushed)
            request_uri = pushed_body.get("request_uri")
            ctx.check(
                "POST /oauth2/par returns a request_uri",
                pushed.status_code == 201 and bool(request_uri),
                ctx.evidence(pushed),
            )
            if request_uri:
                ctx.expose("PAR request_uri", request_uri, note="single-use, pass to /authorize")
            if not request_uri:
                return

            authorized = ctx.api.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": client_id,
                    "redirect_uri": REDIRECT_URI,
                    "request_uri": request_uri,
                    "email": ctx.admin_email or "",
                    "password": ctx.admin_password or "",
                },
            )
            redirect_url = ctx.json(authorized).get("redirect_url") or ""
            code = parse_redirect_params(redirect_url).get("code")
            ctx.check(
                "Authorize consumes the request_uri and returns a code",
                authorized.status_code == 200 and bool(code),
                ctx.evidence(authorized),
            )
            if code:
                bundle, token_resp = ctx.new_client().exchange_code(
                    code=code,
                    verifier=verifier,
                    client_id=client_id,
                    redirect_uri=REDIRECT_URI,
                    auth=basic,
                )
                ctx.check(
                    "The pushed-flow code exchanges for tokens",
                    bool(bundle.access_token),
                    ctx.evidence(token_resp),
                )

            replayed = ctx.api.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": client_id,
                    "redirect_uri": REDIRECT_URI,
                    "request_uri": request_uri,
                    "email": ctx.admin_email or "",
                    "password": ctx.admin_password or "",
                },
            )
            location = replayed.headers.get("location", "")
            error = parse_redirect_params(location).get("error")
            ctx.check(
                "Replaying the request_uri is rejected (single-use)",
                replayed.status_code == 302 and error == "invalid_request",
                ctx.evidence(replayed),
            )
        finally:
            if client_id:
                resp = ctx.api.delete(f"/api/oauth-clients/{client_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(
                        f"could not delete PAR OAuth client {client_id}: HTTP {resp.status_code}"
                    )
