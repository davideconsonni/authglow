"""Pure helpers shared by the check groups.

Kept free of I/O so they can be unit-tested without a live backend.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

#: Human-friendly one-time codes: ``XXXX-XXXX-XXXX`` (email verification,
#: password reset). The backend alphabet excludes ``0``/``O``/``1``/``I``/``L``.
_CODE_RE = re.compile(
    r"(?<![A-Z0-9-])([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})(?![A-Z0-9-])"
)


def extract_code(text: Optional[str]) -> Optional[str]:
    """Return the first ``XXXX-XXXX-XXXX`` code found in *text*, if any."""
    if not text:
        return None
    match = _CODE_RE.search(text.upper())
    return match.group(0) if match else None


def newest_email_code(inbox_body: Any) -> Optional[str]:
    """Extract the code from the newest demo-inbox email that carries one.

    ``inbox_body`` is the JSON returned by ``GET /api/demo/inbox``:
    ``{"emails": [{"body_text": ...}, ...]}`` (newest first).
    """
    if not isinstance(inbox_body, dict):
        return None
    emails = inbox_body.get("emails")
    if not isinstance(emails, list):
        return None
    for email in emails:
        if not isinstance(email, dict):
            continue
        code = extract_code(email.get("body_text"))
        if code:
            return code
    return None


def mask_secret(value: Any, visible: int = 6) -> str:
    """Mask a secret for display, keeping a short recognisable prefix."""
    text = str(value)
    if len(text) <= visible:
        return "***"
    return f"{text[:visible]}…***"


def items_of(body: Any) -> List[Dict[str, Any]]:
    """Normalise a paginated response (``{"items": [...]}`` or a bare list)."""
    if isinstance(body, dict):
        items = body.get("items")
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
    if isinstance(body, list):
        return [i for i in body if isinstance(i, dict)]
    return []
