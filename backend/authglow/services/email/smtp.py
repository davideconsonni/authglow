"""SMTP email provider."""

import asyncio
import smtplib
import ssl
from email.message import EmailMessage as MIMEEmailMessage
from typing import Optional
from uuid import uuid4

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class SMTPEmailProvider(EmailProvider):
    """Send email through an SMTP server using the standard library."""

    def __init__(
        self,
        host: Optional[str],
        port: int = 587,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_tls: bool = True,
        from_email: str = "noreply@authglow.example.com",
        from_name: str = "AuthGlow",
        timeout: float = 30.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.from_email = from_email
        self.from_name = from_name
        self.timeout = timeout

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send a message without blocking the asyncio event loop."""
        message_id = f"smtp-{uuid4()}"
        try:
            mime_message = self._build_message(message, message_id)
            recipients = [str(address) for address in message.to]
            recipients.extend(str(address) for address in message.cc or [])
            recipients.extend(str(address) for address in message.bcc or [])
            await asyncio.to_thread(self._send_sync, mime_message, recipients)
            return EmailSendResult(success=True, message_id=message_id, provider="smtp")
        except Exception as exc:
            return EmailSendResult(success=False, error=str(exc), provider="smtp")

    def _build_message(self, message: EmailMessage, message_id: str) -> MIMEEmailMessage:
        mime_message = MIMEEmailMessage()
        sender = message.from_email or self.from_email
        sender_name = message.from_name or self.from_name
        mime_message["From"] = f"{sender_name} <{sender}>" if sender_name else str(sender)
        mime_message["To"] = ", ".join(str(address) for address in message.to)
        if message.cc:
            mime_message["Cc"] = ", ".join(str(address) for address in message.cc)
        if message.reply_to:
            mime_message["Reply-To"] = str(message.reply_to)
        mime_message["Subject"] = message.subject
        mime_message["Message-ID"] = f"<{message_id}@authglow>"
        for name, value in (message.headers or {}).items():
            mime_message[name] = value

        text = message.body_text or ""
        html = message.body_html
        mime_message.set_content(text)
        if html:
            mime_message.add_alternative(html, subtype="html")
        for attachment in message.attachments or []:
            maintype, _, subtype = attachment.content_type.partition("/")
            mime_message.add_attachment(
                attachment.content,
                maintype=maintype or "application",
                subtype=subtype or "octet-stream",
                filename=attachment.filename,
            )
        return mime_message

    def _send_sync(self, message: MIMEEmailMessage, recipients: list[str]) -> None:
        if not self.host:
            raise ValueError("SMTP_HOST is required")
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as server:
            if self.use_tls:
                server.starttls(context=ssl.create_default_context())
            if self.username:
                server.login(self.username, self.password or "")
            server.send_message(message, to_addrs=recipients)

    def validate_config(self) -> bool:
        """Return whether the required SMTP settings are present."""
        return bool(self.host and self.from_email and (not self.username or self.password))

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "smtp"
