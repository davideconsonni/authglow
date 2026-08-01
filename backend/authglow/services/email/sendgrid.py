"""SendGrid email provider."""

import base64
from typing import Any, Optional
from uuid import uuid4

import httpx

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class SendGridEmailProvider(EmailProvider):
    """Send email through the SendGrid v3 Mail Send API."""

    endpoint = "https://api.sendgrid.com/v3/mail/send"

    def __init__(
        self,
        api_key: Optional[str],
        from_email: str = "noreply@authglow.example.com",
        from_name: str = "AuthGlow",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.from_email = from_email
        self.from_name = from_name
        self.timeout = timeout

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send a message through SendGrid."""
        message_id = f"sendgrid-{uuid4()}"
        try:
            if not self.validate_config():
                raise ValueError("SENDGRID_API_KEY and EMAIL_FROM_ADDRESS are required")
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json=self._payload(message),
                )
            if response.status_code != 202:
                detail = response.text[:500]
                raise RuntimeError(f"SendGrid returned HTTP {response.status_code}: {detail}")
            provider_message_id = response.headers.get("x-message-id") or message_id
            return EmailSendResult(
                success=True, message_id=provider_message_id, provider="sendgrid"
            )
        except Exception as exc:
            return EmailSendResult(success=False, error=str(exc), provider="sendgrid")

    def _payload(self, message: EmailMessage) -> dict[str, Any]:
        sender = message.from_email or self.from_email
        sender_name = message.from_name or self.from_name
        personalization: dict[str, Any] = {
            "to": [{"email": str(address)} for address in message.to],
        }
        if message.cc:
            personalization["cc"] = [{"email": str(address)} for address in message.cc]
        if message.bcc:
            personalization["bcc"] = [{"email": str(address)} for address in message.bcc]
        if message.headers:
            personalization["headers"] = message.headers

        content: list[dict[str, str]] = []
        if message.body_text is not None:
            content.append({"type": "text/plain", "value": message.body_text})
        if message.body_html is not None:
            content.append({"type": "text/html", "value": message.body_html})
        if not content:
            content.append({"type": "text/plain", "value": ""})

        payload: dict[str, Any] = {
            "personalizations": [personalization],
            "from": {"email": str(sender), "name": sender_name},
            "subject": message.subject,
            "content": content,
        }
        if message.reply_to:
            payload["reply_to"] = {"email": str(message.reply_to)}
        if message.attachments:
            payload["attachments"] = [
                {
                    "content": base64.b64encode(attachment.content).decode("ascii"),
                    "filename": attachment.filename,
                    "type": attachment.content_type,
                    "disposition": "attachment",
                }
                for attachment in message.attachments
            ]
        return payload

    def validate_config(self) -> bool:
        """Return whether the API key and sender are configured."""
        return bool(self.api_key and self.from_email)

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "sendgrid"
