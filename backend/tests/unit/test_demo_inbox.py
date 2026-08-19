"""Tests for the demo mailbox and its public inbox endpoint.

The demo inbox lets anonymous visitors of a demo instance read the emails
the server "sent" to their address (verification codes, password reset
codes) when no real mail provider is configured. These tests pin:

1. ``DemoMailbox`` capture / filtering semantics.
2. ``DemoCapturingEmailProvider`` delegating to the real provider while
   recording rendered messages.
3. ``GET /api/demo/inbox`` being a hard ``404`` outside demo mode and
   returning only emails addressed to the queried address in demo mode.
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.demo import router as demo_router
from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.console import ConsoleEmailProvider
from authglow.services.email.demo_mailbox import (
    DemoCapturingEmailProvider,
    DemoMailbox,
    get_demo_mailbox,
    reset_demo_mailbox,
)


def _message(to, subject="Test subject", body="Hello body") -> EmailMessage:
    return EmailMessage(to=to, subject=subject, body_text=body)


def _result() -> EmailSendResult:
    return EmailSendResult(success=True, provider="console")


class TestDemoMailbox:
    """``DemoMailbox`` captures and filters by recipient address."""

    def test_capture_and_list_for(self):
        mailbox = DemoMailbox()
        mailbox.capture(_message(["one@example.com"], subject="Verify"), _result())
        mailbox.capture(_message(["two@example.com"], subject="Reset"), _result())

        inbox = mailbox.list_for("one@example.com")
        assert len(inbox) == 1
        assert inbox[0]["subject"] == "Verify"

    def test_list_for_is_case_insensitive(self):
        mailbox = DemoMailbox()
        mailbox.capture(_message(["ALICE@example.com"]), _result())

        assert len(mailbox.list_for("alice@example.com")) == 1
        assert len(mailbox.list_for("ALICE@EXAMPLE.COM")) == 1

    def test_list_for_newest_first(self):
        mailbox = DemoMailbox()
        mailbox.capture(_message(["a@example.com"], subject="first"), _result())
        mailbox.capture(_message(["a@example.com"], subject="second"), _result())

        assert [e["subject"] for e in mailbox.list_for("a@example.com")] == [
            "second",
            "first",
        ]

    def test_list_for_ignores_other_addresses(self):
        mailbox = DemoMailbox()
        mailbox.capture(_message(["a@example.com"]), _result())

        assert mailbox.list_for("b@example.com") == []


class TestDemoCapturingEmailProvider:
    """The wrapper delegates to the inner provider and captures the email."""

    async def test_delegates_and_captures(self):
        reset_demo_mailbox()
        inner = ConsoleEmailProvider(colorize=False)
        provider = DemoCapturingEmailProvider(inner)

        message = _message(["user@example.com"], body="Your code is ABCD-EFGH-1234")
        result = await provider.send(message)

        assert result.success is True
        assert provider.get_provider_name() == "console"
        assert provider.validate_config() is True

        inbox = get_demo_mailbox().list_for("user@example.com")
        assert len(inbox) == 1
        assert inbox[0]["body_text"] == "Your code is ABCD-EFGH-1234"

    async def test_captures_even_when_inner_provider_fails(self):
        reset_demo_mailbox()
        inner = ConsoleEmailProvider(colorize=False)

        class FailingProvider(ConsoleEmailProvider):
            async def send(self, message):  # noqa: D102
                return EmailSendResult(success=False, error="boom", provider="console")

        provider = DemoCapturingEmailProvider(FailingProvider())

        message = _message(["user@example.com"], body="CODE-ABCD-EFGH-1234")
        result = await provider.send(message)
        assert result.success is False

        inbox = get_demo_mailbox().list_for("user@example.com")
        assert len(inbox) == 1
        assert inbox[0]["body_text"] == "CODE-ABCD-EFGH-1234"


class TestDemoInboxEndpoint:
    """``GET /api/demo/inbox`` is gated on demo mode and filters by address."""

    @staticmethod
    def _client() -> TestClient:
        app = FastAPI()
        app.include_router(demo_router)
        return TestClient(app)

    def test_404_when_demo_disabled(self, test_settings):
        test_settings.demo_mode = False
        client = self._client()
        resp = client.get("/api/demo/inbox", params={"email": "a@example.com"})
        assert resp.status_code == 404

    def test_returns_mailbox_when_demo_enabled(self, test_settings):
        test_settings.demo_mode = True
        reset_demo_mailbox()
        get_demo_mailbox().capture(
            _message(["a@example.com"], subject="Verify your email", body="CODE-1234"),
            _result(),
        )

        client = self._client()
        resp = client.get("/api/demo/inbox", params={"email": "a@example.com"})
        assert resp.status_code == 200
        emails = resp.json()["emails"]
        assert len(emails) == 1
        assert emails[0]["subject"] == "Verify your email"
        assert emails[0]["body_text"] == "CODE-1234"

    def test_filters_by_address(self, test_settings):
        test_settings.demo_mode = True
        reset_demo_mailbox()
        get_demo_mailbox().capture(
            _message(["a@example.com"]), _result()
        )
        get_demo_mailbox().capture(
            _message(["b@example.com"]), _result()
        )

        client = self._client()
        resp = client.get("/api/demo/inbox", params={"email": "b@example.com"})
        assert resp.status_code == 200
        emails = resp.json()["emails"]
        assert len(emails) == 1
        assert emails[0]["to"] == ["b@example.com"]
