"""PII masking helpers.

Centralised utilities for hashing / truncating Personally
Identifiable Information before it is persisted to disk or
emitted to the audit log. Shared between ``AuditService`` and
the three persistent record services
(``LoginHistoryService``, ``SecurityEventService``,
``AdminActionService``) so the masking rules are consistent
across the application.

Design choices:

* ``hash_pii`` is HMAC-SHA256 with ``Settings.secret_key`` as
  the key. The output is the first 16 hex chars — enough to
  group events for the same value (e.g. two login events for
  the same user) without leaking the original.
* ``mask_ip`` truncates IPv4 to ``/24`` and IPv6 to ``/48``.
  This is the convention used by most SIEMs and is enough for
  geo-location without exposing the individual client.
* ``truncate`` caps a string at ``max_len`` with a
  ``\u2026[truncated]`` marker so it is obvious the value was
  clipped.

Pre-existing on-disk records (created before this module
shipped) are *not* back-filled. They will be cleaned up by the
existing retention sweep in each service (90 days for login
history, 365 days for the others).
"""

import hashlib
import hmac
import ipaddress
from typing import Optional

# User-agent length cap. The same value is used by
# ``AuditService._USER_AGENT_MAX_LEN``; the duplication is
# intentional to keep this module dependency-free of the
# audit service.
_USER_AGENT_MAX_LEN = 256

# IP address network prefixes.
_IPV4_PREFIX_LEN = 24
_IPV6_PREFIX_LEN = 48

# Suffix appended when a string is truncated.
_TRUNCATE_MARKER = "\u2026[truncated]"


def hash_pii(value: Optional[str], secret_key: str) -> str:
    """Return a 16-char hex digest of ``value`` keyed with
    ``secret_key``. Stable per (value, secret_key) so events
    for the same value can still be grouped. Not reversible.
    """
    if not value:
        return value or ""
    digest = hmac.new(
        secret_key.encode("utf-8"),
        value.lower().strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:16]


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Truncate an IP address to a network prefix.

    IPv4 -> ``/24`` (e.g. ``"1.2.3.4"`` -> ``"1.2.3.0/24"``).
    IPv6 -> ``/48`` (e.g. ``"2001:db8::1"`` -> ``"2001:db8::/48"``).
    ``None`` is returned unchanged (so callers can distinguish
    "no IP recorded" from "invalid IP"). Empty string is also
    returned unchanged. Invalid input is replaced with
    ``"[invalid_ip]"`` to avoid leaking the original string back
    into the log.
    """
    if ip is None:
        return None
    if not ip:
        return ip
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return "[invalid_ip]"
    prefix_len = _IPV4_PREFIX_LEN if isinstance(addr, ipaddress.IPv4Address) else _IPV6_PREFIX_LEN
    try:
        network = ipaddress.ip_network(f"{addr}/{prefix_len}", strict=False)
    except ValueError:
        return "[invalid_ip]"
    return str(network)


def truncate(value: Optional[str], max_len: int = _USER_AGENT_MAX_LEN) -> str:
    """Truncate ``value`` to at most ``max_len`` characters with a
    marker when clipping happened.
    """
    if value is None or not isinstance(value, str):
        return value  # type: ignore[return-value]
    if len(value) <= max_len:
        return value
    if max_len <= len(_TRUNCATE_MARKER):
        return value[:max_len]
    return value[: max_len - len(_TRUNCATE_MARKER)] + _TRUNCATE_MARKER
