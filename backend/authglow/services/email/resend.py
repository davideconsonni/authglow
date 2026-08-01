"""Resend email provider."""

import base64
from typing import Any, Optional
from uuid import uuid4

import httpx

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class ResendEmailProvider(EmailProvider):
    """Send email through the Resend API."""

    def __init__(
        self,
        api_key: Optional[str],
        base_url: str = "https://api.resend.com",
        from_email: str = "noreply@authglow.example.com",
        from_name: str = "AuthGlow",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.from_email = from_email
        self.from_name = from_name
        self.timeout = timeout

    @property
    def endpoint(self) -> str:
        """Return the Resend email endpoint."""
        return f"{self.base_url}/emails"

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send a message through Resend."""
        message_id = f"resend-{uuid4()}"
        try:
            if not self.validate_config():
                raise ValueError("RESEND_API_KEY and EMAIL_FROM_ADDRESS are required")
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    json=self._payload(message),
                )
            if response.status_code < 200 or response.status_code >= 300:
                detail = response.text[:500]
                raise RuntimeError(f"Resend returned HTTP {response.status_code}: {detail}")
            response_data = response.json()
            return EmailSendResult(
                success=True,
                message_id=response_data.get("id") or message_id,
                provider="resend",
            )
        except Exception as exc:
            return EmailSendResult(success=False, error=str(exc), provider="resend")

    def _payload(self, message: EmailMessage) -> dict[str, Any]:
        """Build the JSON payload expected by Resend."""
        sender = message.from_email or self.from_email
        sender_name = message.from_name or self.from_name
        payload: dict[str, Any] = {
            "from": f"{sender_name} <{sender}>" if sender_name else str(sender),
            "to": [str(address) for address in message.to],
            "subject": message.subject,
        }
        if message.body_text is not None:
            payload["text"] = message.body_text
        if message.body_html is not None:
            payload["html"] = message.body_html
        if message.cc:
            payload["cc"] = [str(address) for address in message.cc]
        if message.bcc:
            payload["bcc"] = [str(address) for address in message.bcc]
        if message.reply_to:
            payload["reply_to"] = [str(message.reply_to)]
        if message.headers:
            payload["headers"] = message.headers
        if message.attachments:
            payload["attachments"] = [
                {
                    "content": base64.b64encode(attachment.content).decode("ascii"),
                    "filename": attachment.filename,
                }
                for attachment in message.attachments
            ]
        return payload

    def validate_config(self) -> bool:
        """Return whether the API key and sender are configured."""
        return bool(self.api_key and self.from_email)

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "resend"
