"""Email service factory for creating configured email providers."""

from functools import lru_cache
from typing import Callable, Dict, Optional

from authglow.core.config import Settings, get_settings
from authglow.services.email.base import EmailProvider, EmailService, EmailTemplateRenderer

# A builder takes the resolved Settings and returns a provider instance.
# Builders lazy-import the concrete class so this module never pays
# import cost (or cycles) for providers that are not selected.
_Builder = Callable[[Settings], EmailProvider]

_PROVIDERS: Dict[str, _Builder] = {}


def register_email_provider(name: str, builder: _Builder) -> None:
    """Register (or replace) a named email provider.

    Third-party providers register without touching this module::

        from authglow.services.email.factory import register_email_provider

        register_email_provider("postmark", lambda s: PostmarkEmailProvider(...))

    The registration must run before :func:`create_email_provider`
    (e.g. import the plugin module at app startup), then
    ``EMAIL_BACKEND=<name>`` resolves to it.
    """
    _PROVIDERS[name] = builder


def _build_console(settings: Settings) -> EmailProvider:
    from .console import ConsoleEmailProvider

    return ConsoleEmailProvider()


def _build_file_storage(settings: Settings) -> EmailProvider:
    from .file_storage import FileStorageEmailProvider

    return FileStorageEmailProvider(settings.email_storage_path)


def _build_smtp(settings: Settings) -> EmailProvider:
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


def _build_sendgrid(settings: Settings) -> EmailProvider:
    from .sendgrid import SendGridEmailProvider

    return SendGridEmailProvider(
        api_key=settings.sendgrid_api_key,
        from_email=settings.email_from_address,
        from_name=settings.email_from_name,
    )


def _build_mailgun(settings: Settings) -> EmailProvider:
    from .mailgun import MailgunEmailProvider

    return MailgunEmailProvider(
        api_key=settings.mailgun_api_key,
        domain=settings.mailgun_domain,
        base_url=settings.mailgun_base_url,
        from_email=settings.email_from_address,
        from_name=settings.email_from_name,
    )


def _build_resend(settings: Settings) -> EmailProvider:
    from .resend import ResendEmailProvider

    return ResendEmailProvider(
        api_key=settings.resend_api_key,
        base_url=settings.resend_base_url,
        from_email=settings.email_from_address,
        from_name=settings.email_from_name,
    )


register_email_provider("console", _build_console)
register_email_provider("file_storage", _build_file_storage)
register_email_provider("smtp", _build_smtp)
register_email_provider("sendgrid", _build_sendgrid)
register_email_provider("mailgun", _build_mailgun)
register_email_provider("resend", _build_resend)


def create_email_provider(
    provider_name: Optional[str] = None,
    *,
    settings: Optional[Settings] = None,
) -> EmailProvider:
    """Create an email provider based on settings.

    Args:
        provider_name: Backend name override (defaults to
            ``settings.email_backend``).
        settings: Already-resolved ``Settings`` (defaults to the
            process singleton from ``get_settings()``). Lets callers
            propagate a patched/test instance instead of patching
            ``get_settings``.
    """
    resolved = settings or get_settings()
    backend = provider_name or resolved.email_backend

    try:
        builder = _PROVIDERS[backend]
    except KeyError:
        raise ValueError(
            f"Unsupported EMAIL_BACKEND '{backend}'. Choose {', '.join(sorted(_PROVIDERS))}."
        ) from None

    provider = builder(resolved)

    # Demo mode: capture every outgoing email in the in-memory demo mailbox
    # so the SPA can surface verification / reset codes to anonymous
    # visitors without a real mail provider. The wrapped provider (e.g.
    # console) keeps its normal behaviour — operator logs are unchanged.
    # ``is True`` (not truthiness): ``demo_mode`` is a ``bool`` and some
    # tests inject MagicMock settings whose attributes are always truthy.
    if resolved.demo_mode is True:
        from .demo_mailbox import DemoCapturingEmailProvider

        provider = DemoCapturingEmailProvider(provider)

    return provider


@lru_cache
def get_email_service() -> EmailService:
    """Get cached email service instance.

    Returns:
        Configured EmailService ready to use
    """
    provider = create_email_provider()
    renderer = EmailTemplateRenderer()
    return EmailService(provider=provider, template_renderer=renderer)
