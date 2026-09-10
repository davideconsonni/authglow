"""Shared helpers for Infobip channel providers."""

from typing import Any, Optional

INFOBIP_SUCCESS_GROUPS = frozenset({"PENDING", "ACCEPTED", "DELIVERED"})


def normalize_base_url(base_url: Optional[str]) -> str:
    """Normalize an Infobip base URL to a full https origin.

    Accepts a bare host (``k98x68.api.infobip.com``) or a full URL and
    returns ``https://<host>`` without trailing slash.
    """
    if not base_url:
        return ""
    value = base_url.strip().rstrip("/")
    if "://" not in value:
        value = f"https://{value}"
    return value


def auth_header(api_key: Optional[str]) -> dict[str, str]:
    """Build the Infobip API-key authorization header."""
    return {"Authorization": f"App {api_key}"}


def is_accepted(status: Any) -> bool:
    """Return whether an Infobip message status means accepted.

    Infobip answers 200 when the message is queued; the per-message
    ``status.groupName`` carries the real outcome (PENDING /
    DELIVERED / UNDELIVERABLE / EXPIRED / REJECTED).
    """
    if not isinstance(status, dict):
        return False
    return str(status.get("groupName", "")).upper() in INFOBIP_SUCCESS_GROUPS
