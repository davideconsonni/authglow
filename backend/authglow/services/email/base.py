"""Base email service interface and abstract classes."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Optional

from authglow.models.email import EmailMessage, EmailSendResult


class EmailProvider(ABC):
    """Abstract base class for email providers.

    All email providers (Console, SMTP, SendGrid, Mailgun, etc.)
    must implement this interface.
    """

    @abstractmethod
    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send an email message.

        Args:
            message: EmailMessage to send

        Returns:
            EmailSendResult with success status and optional message_id
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate provider configuration.

        Returns:
            True if configuration is valid, False otherwise
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of this provider.

        Returns:
            Provider name (e.g., "console", "smtp", "sendgrid")
        """
        pass


class EmailTemplateRenderer:
    """Email template renderer using Jinja2."""

    def __init__(self, template_dir: str = "authglow/templates/emails"):
        """Initialize template renderer.

        Args:
            template_dir: Directory containing email templates
        """
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def render_template(
        self,
        template_name: str,
        context: Dict[str, Any],
        is_html: bool = True
    ) -> str:
        """Render an email template.

        Args:
            template_name: Name of template file (with or without extension)
            context: Template context variables
            is_html: True for HTML templates, False for text

        Returns:
            Rendered template string
        """
        # Add extension if not present
        if not template_name.endswith(('.html', '.txt')):
            extension = '.html' if is_html else '.txt'
            template_name = f"{template_name}{extension}"

        template = self.env.get_template(template_name)
        return template.render(**context)

    def render_both(
        self,
        template_base_name: str,
        context: Dict[str, Any]
    ) -> tuple[Optional[str], Optional[str]]:
        """Render both HTML and text versions of a template.

        Args:
            template_base_name: Base name without extension
            context: Template context variables

        Returns:
            Tuple of (html_content, text_content)
            Either can be None if template doesn't exist
        """
        html_content = None
        text_content = None

        # Try HTML version
        html_path = self.template_dir / f"{template_base_name}.html"
        if html_path.exists():
            html_content = self.render_template(template_base_name, context, is_html=True)

        # Try text version
        text_path = self.template_dir / f"{template_base_name}.txt"
        if text_path.exists():
            text_content = self.render_template(template_base_name, context, is_html=False)

        return html_content, text_content


class EmailService:
    """Main email service that uses a configured provider."""

    def __init__(self, provider: EmailProvider, template_renderer: Optional[EmailTemplateRenderer] = None):
        """Initialize email service.

        Args:
            provider: Email provider implementation
            template_renderer: Optional template renderer for email templates
        """
        self.provider = provider
        self.template_renderer = template_renderer or EmailTemplateRenderer()

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send an email message.

        If message has template_name, renders the template before sending.

        Args:
            message: EmailMessage to send

        Returns:
            EmailSendResult with success status
        """
        # Render template if specified
        if message.template_name and message.template_context:
            html_content, text_content = self.template_renderer.render_both(
                message.template_name,
                message.template_context
            )
            message.body_html = html_content
            message.body_text = text_content

        # Send via provider
        return await self.provider.send(message)

    async def send_template(
        self,
        to: list[str],
        subject: str,
        template_name: str,
        context: Dict[str, Any],
        **kwargs
    ) -> EmailSendResult:
        """Send an email using a template.

        Args:
            to: List of recipient email addresses
            subject: Email subject
            template_name: Template base name (without extension)
            context: Template context variables
            **kwargs: Additional EmailMessage fields

        Returns:
            EmailSendResult with success status
        """
        message = EmailMessage(
            to=to,
            subject=subject,
            template_name=template_name,
            template_context=context,
            **kwargs
        )
        return await self.send(message)

    def validate_config(self) -> bool:
        """Validate email service configuration.

        Returns:
            True if configuration is valid
        """
        return self.provider.validate_config()

    def get_provider_name(self) -> str:
        """Get the name of the current provider.

        Returns:
            Provider name
        """
        return self.provider.get_provider_name()
