"""Console email provider - prints emails to stdout for development."""

import sys
from typing import TextIO
from uuid import uuid4

from authglow.core.datetime import utcnow
from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class ConsoleEmailProvider(EmailProvider):
    """Email provider that prints emails to console/stdout.

    Useful for development and testing. Emails are formatted
    in a readable way with headers and content.
    """

    def __init__(
        self,
        output_stream: TextIO | None = None,
        colorize: bool = True,
        body_stream: TextIO | None = None,
    ):
        """Initialize console email provider.

        Args:
            output_stream: Header stream (default: ``sys.stdout``).
                Receives one short line per email: the message id,
                the recipients, the subject, and any custom
                headers. Safe to mix with the JSON audit log
                stream (VAPT-084).
            colorize: Use ANSI colors for better readability (default: True).
            body_stream: Body stream (default: ``sys.stderr``).
                Receives the full text / HTML body — which may
                contain reset / verification tokens. Splitting
                the body onto ``stderr`` keeps the audit log
                stream clean and gives container log shippers a
                single place to filter out the body if they want.
        """
        self.output = output_stream or sys.stdout
        self.body_stream = body_stream or sys.stderr
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

    def _format_header(self, message: EmailMessage, message_id: str) -> str:
        """Format the email header (safe to mix with the JSON
        audit log stream). VAPT-084.

        Contains the message id, recipients, subject, custom
        headers and priority. **Does not** include the body
        — that goes to ``self.body_stream`` (default
        ``sys.stderr``) so the audit stream is not polluted.
        """
        lines = []

        col_yellow = "\033[33m"
        col_magenta = "\033[35m"
        col_green = "\033[32m"
        col_white_bold = "\033[1;37m"
        col_cyan_bold = "\033[1;36m"

        lines.append("=" * 80)
        lines.append(self._colorize("[EMAIL MESSAGE]", col_cyan_bold))
        lines.append("=" * 80)

        lines.append(f"Message ID: {self._colorize(message_id, col_yellow)}")
        lines.append(f"Timestamp:  {utcnow().isoformat()}Z")
        lines.append(f"Provider:   {self._colorize('console', col_magenta)}")
        lines.append("")

        lines.append(self._colorize("HEADERS:", "\033[1;32m"))
        lines.append("-" * 80)

        from_display = message.from_email or "noreply@authglow.local"
        if message.from_name:
            from_display = f"{message.from_name} <{from_display}>"
        lines.append(f"From:     {self._colorize(from_display, col_green)}")

        to_display = ", ".join(message.to)
        lines.append(f"To:       {self._colorize(to_display, col_green)}")

        if message.cc:
            cc_display = ", ".join(message.cc)
            lines.append(f"CC:       {cc_display}")

        if message.bcc:
            bcc_display = ", ".join(message.bcc)
            lines.append(f"BCC:      {bcc_display}")

        if message.reply_to:
            lines.append(f"Reply-To: {message.reply_to}")

        lines.append(f"Subject:  {self._colorize(message.subject, col_white_bold)}")

        if message.priority.value != "normal":
            lines.append(f"Priority: {message.priority.value.upper()}")

        if message.headers:
            for key, value in message.headers.items():
                lines.append(f"{key}: {value}")

        lines.append("=" * 80)
        lines.append("")

        return "\n".join(lines)

    def _format_body(self, message: EmailMessage) -> str:
        """Format the email body (sent to ``body_stream``). VAPT-084.

        Contains the text / HTML body and attachment metadata.
        The body is the part most likely to contain reset
        / verification tokens, so it is split onto
        ``stderr`` to keep the audit log stream clean.
        """
        lines = []

        if message.body_text:
            lines.append(self._colorize("TEXT VERSION:", "\033[1;34m"))
            lines.append("-" * 80)
            lines.append(message.body_text)
            lines.append("")

        if message.body_html:
            lines.append(self._colorize("HTML VERSION:", "\033[1;34m"))
            lines.append("-" * 80)
            lines.append(message.body_html)
            lines.append("")

        if message.attachments:
            lines.append(self._colorize("ATTACHMENTS:", "\033[1;33m"))
            lines.append("-" * 80)
            for attachment in message.attachments:
                size_kb = len(attachment.content) / 1024
                lines.append(
                    f"- {attachment.filename} ({attachment.content_type}, {size_kb:.2f} KB)"
                )
            lines.append("")

        return "\n".join(lines) if lines else ""

    def _format_email_display(self, message: EmailMessage, message_id: str) -> str:
        """Backwards-compatible single-string format.

        VAPT-084: kept for callers that rely on the combined
        header+body string (e.g. tests). New code should use
        ``format_header`` + ``format_body`` separately.
        """
        return self._format_header(message, message_id) + self._format_body(message)

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send email by printing to console.

        VAPT-084: header (subject, recipients, id) goes to
        ``self.output`` (default ``sys.stdout``); body
        (text / HTML, attachments) goes to ``self.body_stream``
        (default ``sys.stderr``). The split keeps the JSON
        audit log stream clean.
        """
        try:
            message_id = f"console-{uuid4()}"

            header = self._format_header(message, message_id)
            self.output.write(header)
            self.output.flush()

            body = self._format_body(message)
            if body:
                self.body_stream.write(body)
                self.body_stream.flush()

            return EmailSendResult(success=True, message_id=message_id, provider="console")

        except Exception as e:
            return EmailSendResult(success=False, error=str(e), provider="console")

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
