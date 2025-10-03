"""Email service package."""

from authglow.services.email.base import EmailProvider, EmailService, EmailTemplateRenderer
from authglow.services.email.console import ConsoleEmailProvider

__all__ = [
    "EmailProvider",
    "EmailService",
    "EmailTemplateRenderer",
    "ConsoleEmailProvider",
]
