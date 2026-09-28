"""Group: admin OAuth2 client CRUD (create, read, update, lifecycle, rotate, delete)."""

from __future__ import annotations

from typing import Optional

from checktool.registry import Group, GroupContext, register_group

REDIRECT_URI = "http://localhost:9999/callback"


@register_group
class OAuthClientsGroup(Group):
    slug = "oauth_clients"
    title = "OAuth clients (admin)"
    description = (
        "Create a client, list/read/update it, activate/deactivate, rotate its secret "
        "and JWT key, then delete it."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        jwt_client_id: Optional[str] = None
        try:
            created = ctx.request(
                "An OAuth client is created by the admin",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("admin-client"),
                    "redirect_uris": [REDIRECT_URI],
                    "allowed_scopes": ["openid", "profile", "email", "read", "offline_access"],
                    "grant_types": ["authorization_code", "refresh_token"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            )
            body = ctx.json(created)
            client_id = body.get("client_id")
            secret = body.get("client_secret")
            ctx.check(
                "POST /api/oauth-clients returns the secret once",
                created.status_code == 201 and bool(client_id and secret),
                ctx.evidence(created),
            )
            if secret:
                ctx.expose("OAuth client secret", secret, note=f"client_id={client_id}")
            if not client_id:
                return

            listing = ctx.api.get("/api/oauth-clients")
            clients = ctx.json(listing)
            ctx.check(
                "GET /api/oauth-clients lists the new client",
                listing.status_code == 200
                and isinstance(clients, list)
                and any(c.get("client_id") == client_id for c in clients),
                ctx.evidence(listing),
            )

            detail = ctx.api.get(f"/api/oauth-clients/{client_id}")
            ctx.check(
                "GET /api/oauth-clients/{id} never returns the secret",
                detail.status_code == 200 and "client_secret" not in ctx.json(detail),
                ctx.evidence(detail),
            )

            updated = ctx.api.put(
                f"/api/oauth-clients/{client_id}", json={"description": "checktool updated"}
            )
            ctx.check(
                "PUT /api/oauth-clients/{id} updates the client",
                updated.status_code == 200
                and ctx.json(updated).get("description") == "checktool updated",
                ctx.evidence(updated),
            )

            deactivated = ctx.api.post(f"/api/oauth-clients/{client_id}/deactivate")
            after_deactivate = ctx.api.get(f"/api/oauth-clients/{client_id}")
            ctx.check(
                "Deactivate flips is_active off",
                deactivated.status_code == 200
                and ctx.json(after_deactivate).get("is_active") is False,
                ctx.evidence(after_deactivate),
            )

            activated = ctx.api.post(f"/api/oauth-clients/{client_id}/activate")
            after_activate = ctx.api.get(f"/api/oauth-clients/{client_id}")
            ctx.check(
                "Activate flips is_active back on",
                activated.status_code == 200
                and ctx.json(after_activate).get("is_active") is True,
                ctx.evidence(after_activate),
            )

            challenge = ctx.json(
                ctx.api.post(f"/api/oauth-clients/{client_id}/rotate-secret/challenge")
            )
            if challenge.get("word"):
                ctx.expose(
                    "Rotate-secret safeword", challenge["word"], note="echo back in rotate-secret"
                )
            rotated = ctx.api.post(
                f"/api/oauth-clients/{client_id}/rotate-secret",
                json={
                    "challenge_id": challenge.get("challenge_id"),
                    "word": challenge.get("word"),
                },
            )
            new_secret = ctx.json(rotated).get("new_client_secret")
            ctx.check(
                "Rotate-secret returns a new secret",
                rotated.status_code == 200
                and bool(new_secret)
                and new_secret != secret,
                ctx.evidence(rotated),
            )
            if new_secret:
                ctx.expose("Rotated client secret", new_secret, note="plaintext, shown once")

            created_jwt = ctx.request(
                "A client_secret_jwt client is created",
                "POST",
                "/api/oauth-clients",
                json={
                    "client_name": ctx.name("jwt-client"),
                    "redirect_uris": [REDIRECT_URI],
                    "allowed_scopes": ["read"],
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_jwt",
                },
            )
            jwt_body = ctx.json(created_jwt)
            jwt_client_id = jwt_body.get("client_id")
            ctx.check(
                "A client_secret_jwt client is created",
                created_jwt.status_code == 201 and bool(jwt_client_id),
                ctx.evidence(created_jwt),
            )
            if jwt_body.get("client_secret"):
                ctx.expose(
                    "JWT client secret", jwt_body["client_secret"], note=f"client_id={jwt_client_id}"
                )
            if jwt_body.get("client_secret_jwt_key"):
                ctx.expose("JWT client key", jwt_body["client_secret_jwt_key"])
            if jwt_client_id:
                jwt_challenge = ctx.json(
                    ctx.api.post(
                        f"/api/oauth-clients/{jwt_client_id}/rotate-jwt-key/challenge"
                    )
                )
                if jwt_challenge.get("word"):
                    ctx.expose(
                        "Rotate-jwt-key safeword",
                        jwt_challenge["word"],
                        note="echo back in rotate-jwt-key",
                    )
                jwt_rotated = ctx.api.post(
                    f"/api/oauth-clients/{jwt_client_id}/rotate-jwt-key",
                    json={
                        "challenge_id": jwt_challenge.get("challenge_id"),
                        "word": jwt_challenge.get("word"),
                    },
                )
                new_key = ctx.json(jwt_rotated).get("new_client_secret")
                ctx.check(
                    "Rotate-jwt-key returns a new key",
                    jwt_rotated.status_code == 200 and bool(new_key),
                    ctx.evidence(jwt_rotated),
                )
                if new_key:
                    ctx.expose("Rotated JWT client key", new_key, note="plaintext, shown once")
                removed_jwt = ctx.api.delete(f"/api/oauth-clients/{jwt_client_id}")
                if removed_jwt.status_code in (200, 204):
                    jwt_client_id = None

            deleted = ctx.api.delete(f"/api/oauth-clients/{client_id}")
            ctx.check(
                "DELETE /api/oauth-clients/{id} removes the client",
                deleted.status_code in (200, 204),
                ctx.evidence(deleted),
            )
            if deleted.status_code in (200, 204):
                client_id = None
        finally:
            for leftover in (jwt_client_id, client_id):
                if leftover:
                    resp = ctx.api.delete(f"/api/oauth-clients/{leftover}")
                    if resp.status_code not in (200, 204):
                        ctx.warn(
                            f"could not delete test OAuth client {leftover}: HTTP {resp.status_code}"
                        )
