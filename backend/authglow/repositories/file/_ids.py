"""Shared identifier validation for file-backed repositories.

An identifier is used **verbatim** as a filename component by several
repositories (e.g. ``<storage>/federation/<provider_id>.json``). A
caller-supplied value must therefore be restricted to a conservative,
cross-backend-safe character set so it can never:

* escape the repository directory (``../``, ``/``);
* break the path on Windows (``"``, ``:``, ``\\``, ``*``, ``?``, ``<``,
  ``>``, ``|``);
* hit a cloud key restriction (S3 / GCS / ABFS key naming).

The rule is intentionally shared across repositories so the validation
lives next to the path construction and **no caller can bypass it** —
whether the call comes from the HTTP layer, a service, an admin task or
a test.
"""

import re
from typing import Any

# ``^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$``: starts alphanumeric, then up to
# 127 more path-safe characters. ``..`` is rejected separately so a value
# like ``a..b`` (a legal filename) stays allowed while ``..`` cannot.
SAFE_ID_PATTERN = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# WebAuthn credential ids and challenges are base64url, whose alphabet
# includes ``-`` and ``_`` — a value may therefore *start* with either,
# which ``SAFE_ID_PATTERN`` forbids. This pattern covers the base64url
# alphabet (plus optional ``=`` padding) and nothing else: no ``/``, no
# ``\``, no ``.``, so neither path traversal nor a Windows-illegal name
# is possible. The length bound keeps a hostile oversized id from
# building an enormous path.
SAFE_BASE64URL_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_=-]{1,2048}\Z")


def is_safe_entity_id(value: Any) -> bool:
    """Return ``True`` when *value* is safe as a filename component."""
    return (
        isinstance(value, str)
        and ".." not in value
        and SAFE_ID_PATTERN.match(value) is not None
    )


def is_safe_base64url_id(value: Any) -> bool:
    """Return ``True`` for a base64url id safe as a filename component.

    Used for WebAuthn credential ids / challenges, which legitimately
    may begin with ``-`` or ``_``.
    """
    return isinstance(value, str) and SAFE_BASE64URL_ID_PATTERN.match(value) is not None

