"""Email service factory for creating configured email providers."""

from functools import lru_cache
from typing import Optional

from authglow.core.config import get_settings
from authglow.services.email.base import EmailProvider, EmailService, EmailTemplateRenderer


def create_email_provider(provider_name: Optional[str] = None) -> EmailProvider:
    """Create an email provider based on settings."""
    settings = get_settings()
    backend = provider_name or settings.email_backend

    if backend == "file_storage":
        from .file_storage import FileStorageEmailProvider

        return FileStorageEmailProvider(settings.email_storage_path)

    if backend == "smtp":
        from .smtp import SMTPEmailProvider

        return SMTPEmailProvider(
            host=settings.smtp_host,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password,
            use_tls=settings.smtp_use_tls,
            from_email=settings.email_from_address,
            from_name=settings.email_from_name,
        )

    if backend == "sendgrid":
        from .sendgrid import SendGridEmailProvider

        return SendGridEmailProvider(
            api_key=settings.sendgrid_api_key,
            from_email=settings.email_from_address,
            from_name=settings.email_from_name,
        )

    if backend == "mailgun":
        from .mailgun import MailgunEmailProvider

        return MailgunEmailProvider(
            api_key=settings.mailgun_api_key,
            domain=settings.mailgun_domain,
            base_url=settings.mailgun_base_url,
            from_email=settings.email_from_address,
            from_name=settings.email_from_name,
        )

    if backend == "resend":
        from .resend import ResendEmailProvider

        return ResendEmailProvider(
            api_key=settings.resend_api_key,
            base_url=settings.resend_base_url,
            from_email=settings.email_from_address,
            from_name=settings.email_from_name,
        )

    if backend != "console":
        raise ValueError(
            f"Unsupported EMAIL_BACKEND '{backend}'. "
            "Choose console, file_storage, smtp, sendgrid, mailgun, or resend."
        )

    from .console import ConsoleEmailProvider

    return ConsoleEmailProvider()


@lru_cache
def get_email_service() -> EmailService:
    """Get cached email service instance.

    Returns:
        Configured EmailService ready to use
    """
    provider = create_email_provider()
    renderer = EmailTemplateRenderer()
    return EmailService(provider=provider, template_renderer=renderer)
