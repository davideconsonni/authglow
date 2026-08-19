"""In-memory demo mailbox for demo-mode instances.

IMPORTANT — why this module exists (read before an audit flags it):

A demo instance (``Settings.demo_mode = true``) is a public sandbox that
typically has NO mail provider configured, so ``EMAIL_BACKEND`` falls back
to ``console`` and every outgoing email (verification codes, password
reset codes, welcome emails) is printed to ``stderr`` — invisible to the
anonymous visitor who just registered and is waiting for a code.

``DemoMailbox`` closes that gap: when demo mode is enabled the email
provider factory wraps the real provider in
:class:`DemoCapturingEmailProvider`, which delegates the send (so the
console output the operator relies on is unchanged) and ALSO records the
rendered message in an in-process store. A public, rate-limited endpoint
(``GET /api/demo/inbox``) then lets the SPA surface those emails in the
UI, exactly like a Mailpit / Inbucket test inbox.

Security posture:

* The store is ephemeral by design — a module-level list that lives for
  the lifetime of the process and is wiped on every restart, exactly like
  the rest of the stateless demo data model. No email ever touches disk.
* Capture is gated on ``Settings.demo_mode`` inside the factory, so the
  wrapper is never installed on a production (non-demo) instance.
* Exposing verification / reset codes to "anyone who knows the address" is
  the whole point of a demo: the same address-space exposure already
  applies to the boot-time demo password via ``GET /api/meta``, and the
  codes expire within hours.
"""

import threading
from typing import List, Optional, TypedDict

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class CapturedEmail(TypedDict):
    """Shape of an email stored in the demo mailbox."""

    timestamp: str
    to: List[str]
    cc: List[str]
    subject: str
    body_text: Optional[str]
    body_html: Optional[str]
    provider: str


class DemoMailbox:
    """Thread-safe, bounded in-memory store of emails "sent" in demo mode."""

    MAX_EMAILS = 200

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._emails: List[CapturedEmail] = []

    def capture(self, message: EmailMessage, result: EmailSendResult) -> None:
        """Record a rendered message in the demo mailbox.

        Runs on every provider send while demo mode is on. The message has
        already been rendered by ``EmailService.send`` at this point, so
        ``body_text`` / ``body_html`` contain the real codes.
        """
        entry: CapturedEmail = {
            "timestamp": message_template_timestamp(),
            "to": [str(address) for address in message.to],
            "cc": [str(address) for address in (message.cc or [])],
            "subject": message.subject,
            "body_text": message.body_text,
            "body_html": message.body_html,
            "provider": result.provider or "unknown",
        }
        with self._lock:
            self._emails.append(entry)
            if len(self._emails) > self.MAX_EMAILS:
                del self._emails[: len(self._emails) - self.MAX_EMAILS]

    def list_for(self, address: str) -> List[CapturedEmail]:
        """Return every email addressed to *address* (case-insensitive).

        A message is considered addressed to *address* when it appears in
        the ``to`` or ``cc`` recipient lists. Results are returned newest
        first.
        """
        needle = address.lower()
        with self._lock:
            matches = [
                entry
                for entry in self._emails
                if needle
                in {recipient.lower() for recipient in entry["to"] + entry["cc"]}
            ]
        return list(reversed(matches))

    def clear(self) -> None:
        """Empty the mailbox (used by tests and by demo bootstrap)."""
        with self._lock:
            self._emails.clear()


_mailbox: Optional[DemoMailbox] = None
_mailbox_lock = threading.Lock()


def get_demo_mailbox() -> DemoMailbox:
    """Return the process-wide demo mailbox singleton."""
    global _mailbox
    if _mailbox is None:
        with _mailbox_lock:
            if _mailbox is None:
                _mailbox = DemoMailbox()
    return _mailbox


def reset_demo_mailbox() -> None:
    """Replace the singleton with a fresh empty mailbox (test helper)."""
    global _mailbox
    with _mailbox_lock:
        _mailbox = DemoMailbox()


def message_template_timestamp() -> str:
    """RFC-3339 UTC timestamp string for a captured email entry."""
    from authglow.core.datetime import utcnow

    return utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class DemoCapturingEmailProvider(EmailProvider):
    """Provider wrapper that delegates to the real provider AND captures.

    The wrapped provider (typically ``console`` in demo mode) keeps its
    exact behaviour — including stdout / stderr output — while the rendered
    message is additionally stored in the demo mailbox so the SPA can show
    it to the visitor.
    """

    def __init__(self, inner: EmailProvider) -> None:
        self._inner = inner

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Delegate to the inner provider, then capture the message.

        The message is captured regardless of the inner send result: a demo
        may run with ``EMAIL_BACKEND`` set to a provider with no valid
        credentials (send fails), but the visitor must still see their
        verification / reset code in the demo inbox.
        """
        result = await self._inner.send(message)
        get_demo_mailbox().capture(message, result)
        return result

    def validate_config(self) -> bool:
        """Delegate config validation to the wrapped provider."""
        return self._inner.validate_config()

    def get_provider_name(self) -> str:
        """Delegate provider name to the wrapped provider."""
        return self._inner.get_provider_name()
