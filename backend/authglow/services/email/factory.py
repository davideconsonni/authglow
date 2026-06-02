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

    # Default to console
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
