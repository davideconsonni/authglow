"""Group: API key lifecycle (create -> use -> rotate -> revoke -> delete)."""

from __future__ import annotations

from typing import Optional

from checktool.registry import Group, GroupContext, register_group


@register_group
class ApiKeysGroup(Group):
    slug = "api_keys"
    title = "API keys"
    description = "Create a scoped key, authenticate with it, rotate, revoke and delete it."
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        key_id: Optional[str] = None
        try:
            created = ctx.request(
                "A scoped API key is created",
                "POST",
                "/api/keys",
                json={"name": ctx.name("key"), "scopes": ["read"]},
            )
            body = ctx.json(created)
            key_id = body.get("key_id")
            secret = body.get("api_key")
            ctx.check(
                "POST /api/keys returns the plaintext key once",
                created.status_code == 201 and bool(secret),
                ctx.evidence(created),
            )
            if secret:
                ctx.expose("API key", secret, note="plaintext, shown once")
            if not secret or not key_id:
                return

            me = ctx.api.get(
                "/api/users/me", headers={"Authorization": f"Bearer {secret}"}, use_bearer=False
            )
            ctx.check(
                "The API key authenticates against a protected endpoint",
                me.status_code == 200,
                ctx.evidence(me),
            )

            exchanged = ctx.api.request(
                "POST",
                "/api/token/api-key",
                headers={"Authorization": f"Bearer {secret}"},
                use_bearer=False,
            )
            ctx.check(
                "The API key can be exchanged for a JWT access token",
                exchanged.status_code == 200 and bool(ctx.json(exchanged).get("access_token")),
                ctx.evidence(exchanged),
            )

            listing = ctx.api.get("/api/keys")
            items = ctx.json(listing)
            ids = [k.get("key_id") for k in items] if isinstance(items, list) else []
            ctx.check(
                "The key is listed among the owner's keys",
                listing.status_code == 200 and key_id in ids,
                ctx.evidence(listing),
            )

            updated = ctx.api.patch(f"/api/keys/{key_id}", json={"description": "checktool"})
            ctx.check(
                "The key metadata can be updated",
                updated.status_code == 200,
                ctx.evidence(updated),
            )

            # --- rotate (safeword handshake) ------------------------------
            challenge = ctx.api.post(f"/api/keys/{key_id}/rotate/challenge")
            ch = ctx.json(challenge)
            if ch.get("word"):
                ctx.expose("Rotate safeword", ch["word"], note="echo back in the rotate call")
            rotated = ctx.api.post(
                f"/api/keys/{key_id}/rotate",
                json={"challenge_id": ch.get("challenge_id"), "word": ch.get("word")},
            )
            new_secret = ctx.json(rotated).get("api_key")
            ctx.check(
                "Rotation returns a new secret",
                rotated.status_code == 200 and bool(new_secret) and new_secret != secret,
                ctx.evidence(rotated),
            )
            if new_secret:
                ctx.expose("Rotated API key", new_secret, note="plaintext, shown once")
            if new_secret:
                stale = ctx.api.get(
                    "/api/users/me",
                    headers={"Authorization": f"Bearer {secret}"},
                    use_bearer=False,
                )
                ctx.check(
                    "The old secret stops working after rotation",
                    stale.status_code == 401,
                    ctx.evidence(stale),
                )

            # --- revoke ---------------------------------------------------
            revoked = ctx.api.post(f"/api/keys/{key_id}/revoke")
            ctx.check("The key can be revoked", revoked.status_code == 200, ctx.evidence(revoked))

            # --- delete (safeword handshake) ------------------------------
            dch = ctx.json(ctx.api.post(f"/api/keys/{key_id}/delete/challenge"))
            if dch.get("word"):
                ctx.expose("Delete safeword", dch["word"], note="echo back in the delete call")
            deleted = ctx.api.delete(
                f"/api/keys/{key_id}",
                json={"challenge_id": dch.get("challenge_id"), "word": dch.get("word")},
            )
            ctx.check(
                "The key can be permanently deleted",
                deleted.status_code == 200,
                ctx.evidence(deleted),
            )
            if deleted.status_code == 200:
                key_id = None
        finally:
            if key_id:
                resp = ctx.api.delete(
                    f"/api/keys/{key_id}",
                    json=_delete_body(ctx, key_id),
                )
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test API key {key_id}: HTTP {resp.status_code}")


def _delete_body(ctx: GroupContext, key_id: str) -> dict:
    ch = ctx.json(ctx.api.post(f"/api/keys/{key_id}/delete/challenge"))
    return {"challenge_id": ch.get("challenge_id"), "word": ch.get("word")}
