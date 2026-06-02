"""Timezone-aware UTC datetime utility."""

from datetime import datetime, timezone


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
