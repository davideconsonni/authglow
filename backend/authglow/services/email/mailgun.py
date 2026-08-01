"""Mailgun email provider."""

from typing import Optional
from uuid import uuid4

import httpx

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class MailgunEmailProvider(EmailProvider):
    """Send email through the Mailgun Messages API."""

    def __init__(
        self,
        api_key: Optional[str],
        domain: Optional[str],
        base_url: str = "https://api.mailgun.net",
        from_email: str = "noreply@authglow.example.com",
        from_name: str = "AuthGlow",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.domain = domain
        self.base_url = base_url.rstrip("/")
        self.from_email = from_email
        self.from_name = from_name
        self.timeout = timeout

    @property
    def endpoint(self) -> str:
        """Return the Mailgun messages endpoint."""
        return f"{self.base_url}/v3/{self.domain}/messages"

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send a message through Mailgun."""
        message_id = f"mailgun-{uuid4()}"
        try:
            if not self.validate_config():
                raise ValueError(
                    "MAILGUN_API_KEY, MAILGUN_DOMAIN and EMAIL_FROM_ADDRESS are required"
                )
            data, files = self._multipart(message)
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.endpoint,
                    auth=httpx.BasicAuth("api", self.api_key or ""),
                    data=data,
                    files=files or None,
                )
            if response.status_code < 200 or response.status_code >= 300:
                detail = response.text[:500]
                raise RuntimeError(f"Mailgun returned HTTP {response.status_code}: {detail}")
            response_data = response.json()
            return EmailSendResult(
                success=True,
                message_id=response_data.get("id") or message_id,
                provider="mailgun",
            )
        except Exception as exc:
            return EmailSendResult(success=False, error=str(exc), provider="mailgun")

    def _multipart(self, message: EmailMessage) -> tuple[dict[str, str], list[tuple[str, tuple]]]:
        sender = message.from_email or self.from_email
        sender_name = message.from_name or self.from_name
        from_value = f"{sender_name} <{sender}>" if sender_name else str(sender)
        data: dict[str, str] = {
            "from": from_value,
            "to": ",".join(str(address) for address in message.to),
            "subject": message.subject,
        }
        if message.body_text is not None:
            data["text"] = message.body_text
        if message.body_html is not None:
            data["html"] = message.body_html
        if message.cc:
            data["cc"] = ",".join(str(address) for address in message.cc)
        if message.bcc:
            data["bcc"] = ",".join(str(address) for address in message.bcc)
        if message.reply_to:
            data["h:Reply-To"] = str(message.reply_to)
        for name, value in (message.headers or {}).items():
            data[f"h:{name}"] = value
        files = [
            ("attachment", (attachment.filename, attachment.content, attachment.content_type))
            for attachment in message.attachments or []
        ]
        return data, files

    def validate_config(self) -> bool:
        """Return whether the API key, domain and sender are configured."""
        return bool(self.api_key and self.domain and self.from_email)

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "mailgun"
