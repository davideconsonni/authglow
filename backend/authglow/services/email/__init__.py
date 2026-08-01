"""Email service package."""

from authglow.services.email.base import EmailProvider, EmailService, EmailTemplateRenderer
from authglow.services.email.console import ConsoleEmailProvider
from authglow.services.email.file_storage import FileStorageEmailProvider
from authglow.services.email.mailgun import MailgunEmailProvider
from authglow.services.email.resend import ResendEmailProvider
from authglow.services.email.sendgrid import SendGridEmailProvider
from authglow.services.email.smtp import SMTPEmailProvider

__all__ = [
    "EmailProvider",
    "EmailService",
    "EmailTemplateRenderer",
    "ConsoleEmailProvider",
    "FileStorageEmailProvider",
    "SMTPEmailProvider",
    "SendGridEmailProvider",
    "MailgunEmailProvider",
    "ResendEmailProvider",
]
