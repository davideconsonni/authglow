from io import StringIO
from unittest.mock import MagicMock, patch

from authglow.models.email import EmailMessage


class TestConsoleEmailProvider:
    def test_send_email(self):
        from authglow.services.email.console import ConsoleEmailProvider

        output = StringIO()
        provider = ConsoleEmailProvider(output_stream=output, colorize=False)
        message = EmailMessage(
            to=["test@example.com"],
            subject="Test Email",
            body_text="Hello World",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        assert result.provider == "console"
        assert result.message_id.startswith("console-")
        output_str = output.getvalue()
        assert "Test Email" in output_str
        assert "test@example.com" in output_str

    def test_validate_config_always_true(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        assert provider.validate_config() is True

    def test_get_provider_name(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        assert provider.get_provider_name() == "console"

    def test_send_writes_body_to_stderr_vapt_084(self):
        """VAPT-084 — the email body (which may contain reset /
        verification tokens) is split onto ``body_stream``
        (default ``sys.stderr``) while the header (subject,
        recipients, message id) stays on ``output_stream``
        (default ``sys.stdout``). This keeps the JSON audit
        log stream clean.
        """
        import asyncio

        from authglow.services.email.console import ConsoleEmailProvider

        header_output = StringIO()
        body_output = StringIO()
        provider = ConsoleEmailProvider(
            output_stream=header_output,
            body_stream=body_output,
            colorize=False,
        )
        message = EmailMessage(
            to=["recipient@example.com"],
            subject="Reset your password",
            body_text="Click https://app.example.com/reset?token=SECRET123",
        )

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True

        header_str = header_output.getvalue()
        body_str = body_output.getvalue()

        # Subject + recipient + id land in the header stream.
        assert "Reset your password" in header_str
        assert "recipient@example.com" in header_str

        # The actual body (which contains the token) is on the
        # body stream, NOT the header stream.
        assert "SECRET123" not in header_str
        assert "SECRET123" in body_str

    def test_format_header_and_body_are_separate(self):
        """VAPT-084 — ``format_header`` and ``format_body`` are
        independent helpers. ``format_email_display`` is kept
        for back-compat and combines both.
        """
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider(colorize=False)
        message = EmailMessage(
            to=["x@example.com"],
            subject="Subject X",
            body_text="Body Content",
        )

        header = provider._format_header(message, "msg-1")
        body = provider._format_body(message)

        assert "Subject X" in header
        assert "Body Content" not in header
        assert "Subject X" not in body
        assert "Body Content" in body

    def test_default_body_stream_is_stderr(self):
        """VAPT-084 — the default ``body_stream`` is
        ``sys.stderr`` (not ``sys.stdout``) so the JSON audit
        log stream is not polluted with token-bearing bodies.
        """
        import sys

        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        assert provider.body_stream is sys.stderr
        assert provider.output is sys.stdout

    def test_send_with_html_body(self):
        """VAPT-084 — the HTML body lands on ``body_stream`` (not
        the header stream). This test wires both to the same
        StringIO so the assertion is unchanged; the dedicated
        stderr-split test exercises the new behaviour directly.
        """
        from authglow.services.email.console import ConsoleEmailProvider

        output = StringIO()
        provider = ConsoleEmailProvider(output_stream=output, body_stream=output, colorize=False)
        message = EmailMessage(
            to=["html@example.com"],
            subject="HTML Email",
            body_html="<h1>Hello</h1>",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        output_str = output.getvalue()
        assert "<h1>Hello</h1>" in output_str

    def test_colorize_disabled(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider(colorize=False)
        assert provider._colorize("test", "\033[31m") == "test"


class TestFileStorageEmailProvider:
    def test_send_email(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        message = EmailMessage(
            to=["file@example.com"],
            subject="File Test",
            body_text="File content",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        assert result.provider == "file_storage"
        assert result.message_id.startswith("file-")

    def test_validate_config(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails_val")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        assert provider.validate_config() is True

    def test_get_provider_name(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        provider = FileStorageEmailProvider(storage_path=str(tmp_path / "emails_name"))
        assert provider.get_provider_name() == "file_storage"

    def test_send_preserves_metadata(self, tmp_path):
        import json

        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails_meta")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        message = EmailMessage(
            to=["meta@example.com"],
            subject="Metadata Test",
            body_text="Content",
            from_email="sender@example.com",
            from_name="Sender",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True

        import pathlib

        files = list(pathlib.Path(storage_path).glob("*.json"))
        assert len(files) >= 1
        with open(files[0]) as f:
            data = json.load(f)
        assert data["subject"] == "Metadata Test"
        assert data["from"]["email"] == "sender@example.com"
        assert data["from"]["name"] == "Sender"


class TestEmailTemplateRenderer:
    def test_render_auto_adds_html_extension(self, tmp_path):
        from authglow.services.email.base import EmailTemplateRenderer

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "welcome.html").write_text("<h1>Hello {{ name }}</h1>")

        renderer = EmailTemplateRenderer(template_dir=str(template_dir))
        result = renderer.render_template("welcome", {"name": "World"}, is_html=True)
        assert "Hello World" in result

    def test_render_auto_adds_txt_extension(self, tmp_path):
        from authglow.services.email.base import EmailTemplateRenderer

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "welcome.txt").write_text("Hello {{ name }}")

        renderer = EmailTemplateRenderer(template_dir=str(template_dir))
        result = renderer.render_template("welcome", {"name": "World"}, is_html=False)
        assert "Hello World" in result


class TestCreateEmailProvider:
    def test_console_provider_by_default(self):
        from authglow.services.email.console import ConsoleEmailProvider
        from authglow.services.email.factory import create_email_provider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "console"
            provider = create_email_provider()
            assert isinstance(provider, ConsoleEmailProvider)

    def test_file_storage_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.file_storage import FileStorageEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "file_storage"
            mock_settings.return_value.email_storage_path = "/tmp/test_emails"
            provider = create_email_provider()
            assert isinstance(provider, FileStorageEmailProvider)

    def test_unknown_provider_defaults_to_console(self):
        from authglow.services.email.factory import create_email_provider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "unknown"
            import pytest

            with pytest.raises(ValueError, match="Unsupported EMAIL_BACKEND"):
                create_email_provider()

    def test_smtp_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.smtp import SMTPEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "smtp"
            mock_settings.return_value.smtp_host = "smtp.example.com"
            mock_settings.return_value.smtp_port = 587
            mock_settings.return_value.smtp_username = "user"
            mock_settings.return_value.smtp_password = "password"
            mock_settings.return_value.smtp_use_tls = True
            mock_settings.return_value.email_from_address = "noreply@example.com"
            mock_settings.return_value.email_from_name = "AuthGlow"
            provider = create_email_provider()
            assert isinstance(provider, SMTPEmailProvider)

    def test_sendgrid_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.sendgrid import SendGridEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "sendgrid"
            mock_settings.return_value.sendgrid_api_key = "test-key"
            mock_settings.return_value.email_from_address = "noreply@example.com"
            mock_settings.return_value.email_from_name = "AuthGlow"
            provider = create_email_provider()
            assert isinstance(provider, SendGridEmailProvider)

    def test_mailgun_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.mailgun import MailgunEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "mailgun"
            mock_settings.return_value.mailgun_api_key = "test-key"
            mock_settings.return_value.mailgun_domain = "mg.example.com"
            mock_settings.return_value.mailgun_base_url = "https://api.eu.mailgun.net"
            mock_settings.return_value.email_from_address = "noreply@example.com"
            mock_settings.return_value.email_from_name = "AuthGlow"
            provider = create_email_provider()
            assert isinstance(provider, MailgunEmailProvider)

    def test_resend_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.resend import ResendEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "resend"
            mock_settings.return_value.resend_api_key = "test-key"
            mock_settings.return_value.resend_base_url = "https://api.resend.com"
            mock_settings.return_value.email_from_address = "noreply@example.com"
            mock_settings.return_value.email_from_name = "AuthGlow"
            provider = create_email_provider()
            assert isinstance(provider, ResendEmailProvider)


class TestEmailService:
    def test_send_template(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider(output_stream=StringIO(), colorize=False)
        mock_renderer = MagicMock()
        mock_renderer.render_both = MagicMock(return_value=("HTML content", "Text content"))

        service = EmailService(provider=provider, template_renderer=mock_renderer)

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(
            service.send_template(
                to=["test@example.com"],
                subject="Template Test",
                template_name="test_template",
                context={"name": "World"},
            )
        )
        assert result.success is True

    def test_validate_config(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        service = EmailService(provider=provider)
        assert service.validate_config() is True

    def test_get_provider_name(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        service = EmailService(provider=provider)
        assert service.get_provider_name() == "console"
