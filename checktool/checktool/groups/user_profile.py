"""Group: self-service account management (profile, password/email, lifecycle)."""

from __future__ import annotations

import secrets
from typing import Optional

from checktool.registry import Group, GroupContext, register_group


def _strong_password() -> str:
    return "Ct1!" + secrets.token_urlsafe(12)


@register_group
class UserProfileGroup(Group):
    slug = "user_profile"
    title = "User profile & account"
    description = (
        "Profile + preferences, password and email change, self-deactivate/reactivate "
        "and permanent account deletion."
    )
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        # Two independent fixtures: a profile user (whose email is changed) and
        # a lifecycle user (whose login address must stay stable so the
        # deactivate/delete assertions are deterministic).
        profile_id: Optional[str] = None
        life_id: Optional[str] = None
        try:
            profile_id = self._profile_flow(ctx)
            life_id = self._lifecycle_flow(ctx)
        finally:
            for uid in (profile_id, life_id):
                if uid:
                    resp = ctx.api.delete(f"/api/admin/users/{uid}")
                    if resp.status_code not in (200, 204):
                        ctx.warn(f"could not delete test user {uid}: HTTP {resp.status_code}")

    def _create_user(self, ctx: GroupContext, label: str) -> tuple[Optional[str], str, str]:
        email = ctx.email(label)
        password = _strong_password()
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
        return user_id, email, password

    def _profile_flow(self, ctx: GroupContext) -> Optional[str]:
        user_id, email, password = self._create_user(ctx, "profile-user")
        if not user_id:
            return None

        client = ctx.new_client()
        client.admin_login(email, password)

        profile = client.get("/api/profile/me")
        ctx.check(
            "GET /api/profile/me returns the signed-in profile",
            profile.status_code == 200 and ctx.json(profile).get("email") == email,
            ctx.evidence(profile),
        )

        updated = client.patch("/api/profile/me", json={"first_name": "Profiled"})
        ctx.check(
            "PATCH /api/profile/me updates the name",
            updated.status_code == 200 and ctx.json(updated).get("first_name") == "Profiled",
            ctx.evidence(updated),
        )

        preferences = client.get("/api/profile/me/preferences")
        ctx.check(
            "GET /api/profile/me/preferences returns preferences",
            preferences.status_code == 200,
            ctx.evidence(preferences),
        )

        pref_update = client.patch("/api/profile/me/preferences", json={"theme": "dark"})
        ctx.check(
            "PATCH /api/profile/me/preferences persists a preference",
            pref_update.status_code == 200 and ctx.json(pref_update).get("theme") == "dark",
            ctx.evidence(pref_update),
        )

        new_password = _strong_password()
        changed = client.post(
            "/api/profile/me/change-password",
            json={"current_password": password, "new_password": new_password},
        )
        ctx.check(
            "POST /api/profile/me/change-password succeeds",
            changed.status_code == 200,
            ctx.evidence(changed),
        )
        if changed.status_code == 200:
            ctx.expose("New user password", new_password, note=f"login as {email}", api=client)
        client = ctx.new_client()
        bundle = client.admin_login(email, new_password)
        ctx.check(
            "The user can log in with the new password",
            bool(bundle.access_token),
            "no access_token",
        )

        new_email = ctx.email("profile-user-new")
        email_change = client.post(
            "/api/profile/me/change-email",
            json={"new_email": new_email, "password": new_password},
        )
        ctx.check(
            "POST /api/profile/me/change-email succeeds",
            email_change.status_code == 200,
            ctx.evidence(email_change),
        )
        reflected = ctx.json(client.get("/api/profile/me")).get("email")
        ctx.check(
            "The profile reflects the new email",
            reflected == new_email,
            str(reflected),
        )
        ctx.expose(
            "New profile email",
            new_email,
            note="login index still uses the original address",
            secret=False,
            api=client,
        )
        return user_id

    def _lifecycle_flow(self, ctx: GroupContext) -> Optional[str]:
        user_id, email, password = self._create_user(ctx, "lifecycle-user")
        if not user_id:
            return None

        client = ctx.new_client()
        client.admin_login(email, password)

        challenge = client.post("/api/profile/me/deactivate/challenge")
        ch = ctx.json(challenge)
        deactivated = client.post(
            "/api/profile/me/deactivate",
            json={"challenge_id": ch.get("challenge_id"), "word": ch.get("word")},
        )
        ctx.check(
            "POST /api/profile/me/deactivate deactivates the account",
            deactivated.status_code == 200,
            ctx.evidence(deactivated),
        )

        record = ctx.api.get(f"/api/admin/users/{user_id}")
        ctx.check(
            "The account is marked inactive",
            ctx.json(record).get("is_active") is False,
            ctx.evidence(record),
        )
        ctx.check(
            "A deactivated account can no longer log in",
            not _can_login(ctx, email, password),
            "login still succeeded",
        )

        reactivated = ctx.api.put(f"/api/admin/users/{user_id}", json={"is_active": True})
        ctx.check(
            "An admin can reactivate the account",
            reactivated.status_code == 200,
            ctx.evidence(reactivated),
        )

        client = ctx.new_client()
        bundle = client.admin_login(email, password)
        ctx.check(
            "The reactivated account can log in again",
            bool(bundle.access_token),
            "no access_token",
        )

        deleted = client.delete(
            "/api/profile/me",
            json={"password": password, "confirmation": "DELETE"},
        )
        ctx.check(
            "DELETE /api/profile/me deletes the account",
            deleted.status_code == 200,
            ctx.evidence(deleted),
        )
        if deleted.status_code == 200:
            ctx.check(
                "A deleted account can no longer log in",
                not _can_login(ctx, email, password),
                "login still succeeded",
            )
            return None
        return user_id


def _can_login(ctx: GroupContext, email: str, password: str) -> bool:
    """Return True if a browser-style login yields an authorization code."""
    client = ctx.new_client()
    cfg = client.oidc_config()
    result = client.authorize_code(
        email=email,
        password=password,
        client_id=cfg.get("client_id", ""),
        redirect_uri=cfg.get("redirect_uri", ""),
    )
    return bool(result.get("code"))
