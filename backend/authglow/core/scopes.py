"""Scope-token helpers shared by the ingestion models.

RFC 6749 §3.3 restricts a scope-token to ``%x21 / %x23-5B /
%x5D-7E`` — printable ASCII minus space (the list separator) and
double-quote (the string delimiter). On top of that charset we
explicitly REJECT commas: OAuth2/OIDC scope lists are SPACE-delimited
and ``read,write`` is always somebody's CSV habit, never a real
token name. These helpers make every ingestion point enforce exactly
that — no CSV leniency.
"""

import re
from typing import List

# RFC 6749 §3.3 scope-token charset.
SCOPE_TOKEN_RE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")

#: Scope tokens that can no longer be minted anywhere. Admin authority
#: is RBAC-driven (assign the "Authglow Administrator" role instead —
#: see ``authglow.models.rbac.ADMIN_ROLE_NAME``); carrying it as an
#: OAuth scope has no effect, so ingestion rejects it loudly rather
#: than silently accepting a dead value.
RESERVED_SCOPE_TOKENS = frozenset({"admin"})


def _is_valid_scope_token(token: str) -> bool:
    """RFC charset AND no commas (never a valid list separator here)."""
    return bool(SCOPE_TOKEN_RE.match(token)) and "," not in token


def validate_scope_tokens(scopes: List[str]) -> List[str]:
    """Return *scopes* unchanged when every token is compliant.

    Raises ``ValueError`` listing the offending tokens otherwise.
    Intended for Pydantic ``field_validator`` hooks so malformed
    input becomes a 422 at the API boundary.
    """
    invalid = sorted({s for s in (scopes or []) if not _is_valid_scope_token(s)})
    reserved = sorted({s for s in (scopes or []) if s in RESERVED_SCOPE_TOKENS})
    if invalid:
        raise ValueError(
            "Invalid scope token(s): "
            + ", ".join(repr(s) for s in invalid)
            + " — scopes are SPACE-delimited strings per RFC 6749 §3.3 "
            "(each token: printable ASCII, no spaces or commas)"
        )
    if reserved:
        raise ValueError(
            "Reserved scope token(s): "
            + ", ".join(repr(s) for s in reserved)
            + " — admin authority is RBAC-driven; assign the "
            "'Authglow Administrator' role instead of the 'admin' scope"
        )
    return list(scopes or [])
