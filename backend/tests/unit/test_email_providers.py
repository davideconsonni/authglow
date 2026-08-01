"""Unit tests for external email providers without network access."""

from unittest.mock import MagicMock

from authglow.models.email import EmailMessage
from authglow.services.email.mailgun import MailgunEmailProvider
from authglow.services.email.resend import ResendEmailProvider
from authglow.services.email.sendgrid import SendGridEmailProvider
from authglow.services.email.smtp import SMTPEmailProvider


def _message() -> EmailMessage:
    return EmailMessage(
        to=["to@example.com"],
        cc=["cc@example.com"],
        bcc=["bcc@example.com"],
        subject="Test subject",
        body_text="Plain text",
        body_html="<p>HTML</p>",
        from_email="sender@example.com",
        from_name="Sender",
        reply_to="reply@example.com",
    )


class TestSMTPEmailProvider:
    async def test_send_offloads_smtp_and_builds_message(self, monkeypatch):
        provider = SMTPEmailProvider(
            host="smtp.example.com",
            username="user",
            password="password",
            from_email="sender@example.com",
        )
        send_sync = MagicMock()
        monkeypatch.setattr(provider, "_send_sync", send_sync)

        result = await provider.send(_message())

        assert result.success is True
        assert result.provider == "smtp"
        send_sync.assert_called_once()
        mime_message, recipients = send_sync.call_args.args
        assert mime_message["Subject"] == "Test subject"
        assert recipients == ["to@example.com", "cc@example.com", "bcc@example.com"]

    def test_validate_config(self):
        assert SMTPEmailProvider(host="smtp.example.com", from_email="a@example.com").validate_config()
        assert not SMTPEmailProvider(host=None, from_email="a@example.com").validate_config()
        assert not SMTPEmailProvider(
            host="smtp.example.com", username="user", password=None, from_email="a@example.com"
        ).validate_config()


class FakeHTTPResponse:
    def __init__(self, status_code=202, headers=None, payload=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload or {}
        self.text = text

    def json(self):
        return self._payload


class FakeAsyncClient:
    response = FakeHTTPResponse()
    calls = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return None

    async def post(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return self.response


class TestSendGridEmailProvider:
    async def test_send_posts_mail_send_payload(self, monkeypatch):
        FakeAsyncClient.calls = []
        FakeAsyncClient.response = FakeHTTPResponse(
            headers={"x-message-id": "sg-message-id"}
        )
        monkeypatch.setattr(
            "authglow.services.email.sendgrid.httpx.AsyncClient", FakeAsyncClient
        )
        provider = SendGridEmailProvider("api-key", from_email="sender@example.com")

        result = await provider.send(_message())

        assert result.success is True
        assert result.message_id == "sg-message-id"
        _, request = FakeAsyncClient.calls[0]
        payload = request["json"]
        assert payload["subject"] == "Test subject"
        assert payload["personalizations"][0]["cc"][0]["email"] == "cc@example.com"
        assert payload["content"][1]["type"] == "text/html"

    def test_validate_config(self):
        assert SendGridEmailProvider("api-key", "sender@example.com").validate_config()
        assert not SendGridEmailProvider(None, "sender@example.com").validate_config()


class TestMailgunEmailProvider:
    async def test_send_posts_messages_payload(self, monkeypatch):
        FakeAsyncClient.calls = []
        FakeAsyncClient.response = FakeHTTPResponse(
            status_code=200,
            payload={"id": "<mailgun-message-id>"},
        )
        monkeypatch.setattr(
            "authglow.services.email.mailgun.httpx.AsyncClient", FakeAsyncClient
        )
        provider = MailgunEmailProvider(
            "api-key",
            "mg.example.com",
            base_url="https://api.eu.mailgun.net",
            from_email="sender@example.com",
        )

        result = await provider.send(_message())

        assert result.success is True
        assert result.message_id == "<mailgun-message-id>"
        args, request = FakeAsyncClient.calls[0]
        assert args[0] == "https://api.eu.mailgun.net/v3/mg.example.com/messages"
        assert request["data"]["to"] == "to@example.com"
        assert request["data"]["h:Reply-To"] == "reply@example.com"

    def test_validate_config(self):
        assert MailgunEmailProvider("api-key", "mg.example.com").validate_config()
        assert not MailgunEmailProvider("api-key", None).validate_config()


class TestResendEmailProvider:
    async def test_send_posts_email_payload(self, monkeypatch):
        FakeAsyncClient.calls = []
        FakeAsyncClient.response = FakeHTTPResponse(
            status_code=200,
            payload={"id": "resend-message-id"},
        )
        monkeypatch.setattr(
            "authglow.services.email.resend.httpx.AsyncClient", FakeAsyncClient
        )
        provider = ResendEmailProvider(
            "api-key",
            base_url="https://api.resend.com",
            from_email="sender@example.com",
        )

        result = await provider.send(_message())

        assert result.success is True
        assert result.message_id == "resend-message-id"
        args, request = FakeAsyncClient.calls[0]
        assert args[0] == "https://api.resend.com/emails"
        assert request["headers"]["Authorization"] == "Bearer api-key"
        assert request["json"]["to"] == ["to@example.com"]
        assert request["json"]["cc"] == ["cc@example.com"]
        assert request["json"]["reply_to"] == ["reply@example.com"]

    def test_validate_config(self):
        assert ResendEmailProvider("api-key", from_email="sender@example.com").validate_config()
        assert not ResendEmailProvider(None, from_email="sender@example.com").validate_config()
