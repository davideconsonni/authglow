"""Email service package."""

from authglow.services.email.base import EmailProvider, EmailService, EmailTemplateRenderer
from authglow.services.email.console import ConsoleEmailProvider
from authglow.services.email.file_storage import FileStorageEmailProvider

__all__ = [
    "EmailProvider",
    "EmailService",
    "EmailTemplateRenderer",
    "ConsoleEmailProvider",
    "FileStorageEmailProvider",
]
