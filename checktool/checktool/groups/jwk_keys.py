"""Group: JWT signing-key rotation (intrusive — gated on local/--yes targets)."""

from __future__ import annotations

from checktool.registry import Group, GroupContext, register_group


@register_group
class JwkKeysGroup(Group):
    slug = "jwk_keys"
    title = "Signing keys"
    description = (
        "Read the keyring, prove the active key cannot be revoked, then (local/--yes "
        "only) rotate the signing key, verify JWKS and revoke the retired key."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        keys = ctx.request("The signing keyring is read", "GET", "/api/admin/jwk-keys")
        body = ctx.json(keys)
        active_kid = body.get("active_kid")
        ctx.check(
            "GET /api/admin/jwk-keys returns the active key",
            keys.status_code == 200
            and bool(active_kid)
            and any(k.get("kid") == active_kid for k in body.get("keys", [])),
            ctx.evidence(keys),
        )
        if not active_kid:
            return

        refused = ctx.api.post(f"/api/admin/jwk-keys/{active_kid}/revoke")
        ctx.check(
            "The active signing key cannot be revoked (400)",
            refused.status_code == 400,
            ctx.evidence(refused),
        )

        if not (ctx.config.is_local or ctx.config.yes):
            ctx.skip(
                "Signing-key rotation",
                "rotating the live key is intrusive on a shared/remote instance; pass --yes",
            )
            return

        challenge = ctx.json(ctx.api.post("/api/admin/jwk-keys/rotate/challenge"))
        if challenge.get("word"):
            ctx.expose("Key-rotate safeword", challenge["word"], note="echo back in rotate")
        rotated = ctx.api.post(
            "/api/admin/jwk-keys/rotate",
            json={
                "challenge_id": challenge.get("challenge_id"),
                "word": challenge.get("word"),
            },
        )
        rotated_body = ctx.json(rotated)
        old_kid = rotated_body.get("old_kid")
        new_kid = rotated_body.get("new_kid")
        ctx.check(
            "POST /api/admin/jwk-keys/rotate activates a new key",
            rotated.status_code == 200 and bool(new_kid) and new_kid != old_kid,
            ctx.evidence(rotated),
        )
        if old_kid:
            ctx.expose("Retired signing key kid", old_kid, secret=False)
        if new_kid:
            ctx.expose("New active signing key kid", new_kid, secret=False)
        if not new_kid:
            return

        jwks = ctx.api.get("/.well-known/jwks.json")
        published = [k.get("kid") for k in ctx.json(jwks).get("keys", [])]
        ctx.check(
            "The new key is published in JWKS",
            jwks.status_code == 200 and new_kid in published,
            ctx.evidence(jwks),
        )

        # Re-bind the shared admin client to a token signed by the new key
        # before revoking the retired one (its token signed the old key).
        if ctx.admin_email and ctx.admin_password:
            try:
                ctx.api.admin_login(ctx.admin_email, ctx.admin_password)
            except RuntimeError as exc:
                ctx.warn(f"could not re-login after key rotation: {exc}")

        if old_kid:
            revoked = ctx.api.post(f"/api/admin/jwk-keys/{old_kid}/revoke")
            ctx.check(
                "The retired (non-active) key can be revoked",
                revoked.status_code == 200,
                ctx.evidence(revoked),
            )
