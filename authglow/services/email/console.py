"""Console email provider - prints emails to stdout for development."""

import sys
from datetime import datetime
from uuid import uuid4
from typing import TextIO

from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class ConsoleEmailProvider(EmailProvider):
    """Email provider that prints emails to console/stdout.

    Useful for development and testing. Emails are formatted
    in a readable way with headers and content.
    """

    def __init__(self, output_stream: TextIO = None, colorize: bool = True):
        """Initialize console email provider.

        Args:
            output_stream: Output stream (default: sys.stdout)
            colorize: Use ANSI colors for better readability (default: True)
        """
        self.output = output_stream or sys.stdout
        self.colorize = colorize

    def _colorize(self, text: str, color_code: str) -> str:
        """Add ANSI color codes if colorize is enabled.

        Args:
            text: Text to colorize
            color_code: ANSI color code

        Returns:
            Colorized text or plain text
        """
        if not self.colorize:
            return text
        reset = "\033[0m"
        return f"{color_code}{text}{reset}"

    def _format_email_display(self, message: EmailMessage, message_id: str) -> str:
        """Format email for console display.

        Args:
            message: EmailMessage to format
            message_id: Generated message ID

        Returns:
            Formatted email string
        """
        lines = []

        # Header with colors (use simple text for Windows compatibility)
        lines.append("=" * 80)
        lines.append(self._colorize("[EMAIL MESSAGE]", "\033[1;36m"))  # Cyan bold
        lines.append("=" * 80)

        # Metadata
        lines.append(f"Message ID: {self._colorize(message_id, '\033[33m')}")  # Yellow
        lines.append(f"Timestamp:  {datetime.utcnow().isoformat()}Z")
        lines.append(f"Provider:   {self._colorize('console', '\033[35m')}")  # Magenta
        lines.append("")

        # Headers
        lines.append(self._colorize("HEADERS:", "\033[1;32m"))  # Green bold
        lines.append("-" * 80)

        from_display = message.from_email or "noreply@authglow.local"
        if message.from_name:
            from_display = f"{message.from_name} <{from_display}>"
        lines.append(f"From:     {self._colorize(from_display, '\033[32m')}")

        to_display = ", ".join(message.to)
        lines.append(f"To:       {self._colorize(to_display, '\033[32m')}")

        if message.cc:
            cc_display = ", ".join(message.cc)
            lines.append(f"CC:       {cc_display}")

        if message.bcc:
            bcc_display = ", ".join(message.bcc)
            lines.append(f"BCC:      {bcc_display}")

        if message.reply_to:
            lines.append(f"Reply-To: {message.reply_to}")

        lines.append(f"Subject:  {self._colorize(message.subject, '\033[1;37m')}")  # White bold

        if message.priority.value != "normal":
            lines.append(f"Priority: {message.priority.value.upper()}")

        # Custom headers
        if message.headers:
            for key, value in message.headers.items():
                lines.append(f"{key}: {value}")

        lines.append("")

        # Body content
        if message.body_text:
            lines.append(self._colorize("TEXT VERSION:", "\033[1;34m"))  # Blue bold
            lines.append("-" * 80)
            lines.append(message.body_text)
            lines.append("")

        if message.body_html:
            lines.append(self._colorize("HTML VERSION:", "\033[1;34m"))  # Blue bold
            lines.append("-" * 80)
            lines.append(message.body_html)
            lines.append("")

        # Attachments
        if message.attachments:
            lines.append(self._colorize("ATTACHMENTS:", "\033[1;33m"))  # Yellow bold
            lines.append("-" * 80)
            for attachment in message.attachments:
                size_kb = len(attachment.content) / 1024
                lines.append(
                    f"- {attachment.filename} "
                    f"({attachment.content_type}, {size_kb:.2f} KB)"
                )
            lines.append("")

        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send email by printing to console.

        Args:
            message: EmailMessage to "send"

        Returns:
            EmailSendResult with success=True and generated message_id
        """
        try:
            # Generate unique message ID
            message_id = f"console-{uuid4()}"

            # Format and print
            formatted = self._format_email_display(message, message_id)
            self.output.write(formatted)
            self.output.flush()

            return EmailSendResult(
                success=True,
                message_id=message_id,
                provider="console"
            )

        except Exception as e:
            return EmailSendResult(
                success=False,
                error=str(e),
                provider="console"
            )

    def validate_config(self) -> bool:
        """Validate console provider configuration.

        Console provider has no configuration requirements.

        Returns:
            Always True
        """
        return True

    def get_provider_name(self) -> str:
        """Get provider name.

        Returns:
            "console"
        """
        return "console"
