"""Event Catalog for webhook delivery.

CLOSED set of event types an admin can subscribe a Webhook Endpoint to.
Both the CRUD validation (``api/webhooks.py``) and the emitters (B2,
dispatcher) import the constants from this module so the two sides cannot
drift apart. A type outside this catalog cannot be subscribed to nor
emitted — adding one is a deliberate code change here.
"""

from typing import Final, Tuple

USER_CREATED: Final[str] = "user.created"
USER_UPDATED: Final[str] = "user.updated"
USER_DELETED: Final[str] = "user.deleted"
LOGIN_SUCCESS: Final[str] = "login.success"
LOGIN_FAILED: Final[str] = "login.failed"
PASSWORD_CHANGED: Final[str] = "password.changed"
MFA_ENROLLED: Final[str] = "mfa.enrolled"
SESSION_REVOKED: Final[str] = "session.revoked"
WEBHOOK_TEST: Final[str] = "webhook.test"

EVENT_TYPES: Final[Tuple[str, ...]] = (
    USER_CREATED,
    USER_UPDATED,
    USER_DELETED,
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    PASSWORD_CHANGED,
    MFA_ENROLLED,
    SESSION_REVOKED,
    WEBHOOK_TEST,
)

VALID_EVENT_TYPES: Final[frozenset] = frozenset(EVENT_TYPES)
