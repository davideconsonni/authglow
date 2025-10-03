"""Email service factory for creating configured email providers."""

from functools import lru_cache

from authglow.services.email.base import EmailService, EmailProvider, EmailTemplateRenderer
from authglow.services.email.console import ConsoleEmailProvider
from authglow.services.email.file_storage import FileStorageEmailProvider
from authglow.core.config import get_settings


def create_email_provider(provider_name: str = None) -> EmailProvider:
    """Create an email provider based on configuration.

    Args:
        provider_name: Override provider name from settings

    Returns:
        Configured EmailProvider instance

    Raises:
        ValueError: If provider is unknown or not configured
    """
    settings = get_settings()
    provider = provider_name or settings.email_provider

    if provider == "console":
        return ConsoleEmailProvider(colorize=True)

    elif provider == "file" or provider == "file_storage":
        return FileStorageEmailProvider(storage_path=f"{settings.storage_path}/emails")

    elif provider == "smtp":
        # TODO: Implement SMTP provider
        raise NotImplementedError("SMTP provider not yet implemented. Use 'console' for now.")

    elif provider == "sendgrid":
        # TODO: Implement SendGrid provider
        raise NotImplementedError("SendGrid provider not yet implemented. Use 'console' for now.")

    elif provider == "mailgun":
        # TODO: Implement Mailgun provider
        raise NotImplementedError("Mailgun provider not yet implemented. Use 'console' for now.")

    else:
        raise ValueError(
            f"Unknown email provider: {provider}. "
            f"Supported providers: console, file, file_storage, smtp, sendgrid, mailgun"
        )


@lru_cache
def get_email_service() -> EmailService:
    """Get cached email service instance.

    Returns:
        Configured EmailService ready to use
    """
    provider = create_email_provider()
    renderer = EmailTemplateRenderer()
    return EmailService(provider=provider, template_renderer=renderer)
