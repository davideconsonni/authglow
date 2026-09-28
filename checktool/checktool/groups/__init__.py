"""Group registration.

Importing each module runs its ``@register_group`` decorator. The import
order below is the order groups are presented and run in.
"""

from checktool.groups import (  # noqa: F401
    admin_insights,
    admin_users,
    api_keys,
    auth,
    bootstrap,
    claim_policy,
    consents,
    demo_inbox,
    device_auth,
    email_verification,
    federation,
    jwk_keys,
    mfa,
    oauth2,
    oauth_clients,
    par,
    passkeys,
    password_reset,
    phone_verification,
    rbac,
    sessions,
    settings,
    user_profile,
    webhooks,
)

__all__ = [
    "bootstrap",
    "auth",
    "oauth2",
    "api_keys",
    "rbac",
    "admin_users",
    "user_profile",
    "federation",
    "claim_policy",
    "sessions",
    "admin_insights",
    "mfa",
    "email_verification",
    "password_reset",
    "device_auth",
    "par",
    "consents",
    "oauth_clients",
    "webhooks",
    "jwk_keys",
    "settings",
    "phone_verification",
    "passkeys",
    "demo_inbox",
]
