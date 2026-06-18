"""Authentication Context Class Reference (ACR) and Authentication
Methods References (AMR) logic.

OIDC Core defines ``acr`` and ``amr`` as ID Token claims that allow
Relying Parties to differentiate authentication strength (e.g. password
vs MFA vs passkey).  This module provides a static mapping and a
``compute_acr`` helper consumed by the ID token creation path.

ACR levels (OIDC Core §2, §5.5.1.1):
    0 — no explicit authentication
    1 — password
    2 — password + TOTP / backup code
    3 — passkey (WebAuthn)
"""

from typing import List

AUTH_METHOD_PASSWORD = "pwd"
AUTH_METHOD_TOTP = "mfa"
AUTH_METHOD_BACKUP = "backup"
AUTH_METHOD_WEBAUTHN = "pop"

ACR_LEVEL_ZERO = "0"
ACR_LEVEL_PASSWORD = "1"
ACR_LEVEL_MFA = "2"
ACR_LEVEL_PASSKEY = "3"

_METHOD_TO_LEVEL: dict[str, int] = {
    AUTH_METHOD_PASSWORD: 1,
    AUTH_METHOD_TOTP: 2,
    AUTH_METHOD_BACKUP: 2,
    AUTH_METHOD_WEBAUTHN: 3,
}


def compute_acr(auth_methods: List[str]) -> str:
    """Return the highest ACR level achieved by *auth_methods*.

    Returns ``"0"`` when *auth_methods* is empty so callers can
    distinguish ``None`` (not set) from ``"0"`` (explicitly no auth).
    """
    if not auth_methods:
        return ACR_LEVEL_ZERO
    return str(max(_METHOD_TO_LEVEL.get(m, 0) for m in auth_methods))
