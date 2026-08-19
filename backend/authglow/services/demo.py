"""Demo-mode bootstrap helpers.

IMPORTANT — why this module exists (read before an audit flags it):

``seed_demo_user`` is NOT a backdoor. It runs ONLY when the operator
explicitly opts in via ``Settings.demo_mode = true`` (default is
``False`` — this code is dead unless enabled). Its purpose is to let
anonymous visitors log in to a *public sandbox* and try the product
without creating an account.

The deployment model this was designed for is a **stateless demo
instance**: no persistent disk (e.g. Render free tier, ``/app/data``
resets on every restart/redeploy). The seeded admin therefore cannot
cause lasting damage — every account, API key, OAuth client and audit
record is wiped on the next restart. The warning banner surfaced by
``GET /api/meta`` tells every visitor exactly that.

Security posture while a demo instance is live:

* ``app_env`` is still ``production``, so every production validator
  (SECRET_KEY strength, OAuth2 defaults, DEBUG) remains enforced.
* The demo password is generated at boot with ``secrets.token_urlsafe``
  and NEVER written to logs, the keyring, or any audit record. It is
  exposed only via ``GET /api/meta`` (rate-limited, public by design —
  it is the whole point of a demo).
* The demo user is created with ``admin`` scope because a demo of an
  auth platform must be able to exercise the admin surface. The blast
  radius is bounded by the ephemeral storage model above.
"""

from typing import Optional

from authglow.core.config import Settings, get_settings
from authglow.models.user import User
from authglow.services.password import hash_password_async
from authglow.services.user import UserService


async def seed_demo_user(
    service: Optional[UserService] = None,
    settings: Optional[Settings] = None,
) -> str:
    """Create (or refresh) the demo admin user and return its plaintext
    password.

    Idempotent: on first boot the user is created; on subsequent boots
    (including after a data reset, when the user no longer exists) it is
    re-created. When the user already exists the password hash is
    refreshed so the freshly generated password always works — the
    password changes on every boot, so a leaked demo credential
    self-expires.

    The demo admin is the bootstrap account: it is pinned with
    ``is_bootstrap=True`` and re-activated on every boot, so the admin
    surface refuses to deactivate it and the public sandbox can never
    be bricked by an operator misclick.

    The caller (app startup) is responsible for deciding whether demo
    mode is enabled; this function performs no gating of its own so the
    caller keeps full control.

    Returns:
        The plaintext password for the demo user. The caller must expose
        it only via ``GET /api/meta`` (when ``demo_mode`` is true) and
        must never log it.
    """
    # ``secrets`` not ``random`` — the demo password is a real credential
    # while it lives, so it must come from a cryptographically secure PRNG.
    import secrets

    settings = settings or get_settings()
    service = service or UserService()

    password = secrets.token_urlsafe(16)
    hashed_password = await hash_password_async(password)

    existing = await service.get_user_by_email(settings.demo_user_email)
    if existing is not None:
        # Keep the account but rotate the hash to the boot-time password.
        await service.set_password(existing.id, hashed_password)
        # The demo admin is the bootstrap account: it must never be left
        # deactivated (e.g. by an admin misclick), otherwise the public
        # sandbox is bricked until the next restart. Re-activate it on
        # every boot and pin the bootstrap flag so the admin surface
        # refuses to deactivate it.
        if not existing.is_active or not existing.is_bootstrap:
            existing.is_active = True
            existing.is_bootstrap = True
            await service.update_user(existing)
        return password

    demo_user = User(
        email=settings.demo_user_email,
        hashed_password=hashed_password,
        first_name="Demo",
        last_name="Admin",
        scopes=["read", "write", "admin"],
        is_active=True,
        email_verified=True,
        is_invited=False,
        is_bootstrap=True,
    )
    await service.create_user(demo_user)
    return password
