"""Security notifications service."""

from typing import Optional

import structlog

from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.user import User
from authglow.services.email.factory import get_email_service

# VAPT-083: ``print(...)`` for email-send failures bypasses
# structlog (no JSON, no timestamp, no level, no masking).
# Plaintext on the same stream as the JSON audit log makes
# ingest messy. All send-failure paths now go through
# ``authglow.email.warning``.
_email_log = structlog.get_logger("authglow.email")


class SecurityNotificationService:
    """Service for sending security-related email notifications."""

    def __init__(self):
        """Initialize security notification service."""
        self.settings = get_settings()
        self.email_service = get_email_service()

    async def send_login_alert(
        self,
        user: User,
        ip_address: Optional[str] = None,
        device: Optional[str] = None,
        browser: Optional[str] = None,
        location: Optional[str] = None,
        was_you: bool = True,
    ) -> bool:
        """Send login alert email.

        Args:
            user: User who logged in
            ip_address: IP address of login
            device: Device information
            browser: Browser information
            location: Geographic location
            was_you: Whether this is expected to be the user

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": "a new login to your account",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "device": device,
                "browser": browser,
                "location": location,
                "was_you": was_you,
                "security_url": f"{self.settings.frontend_base_url}/admin",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"New login to your {self.settings.company_name} account",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="login_alert",
                user_id=user.id,
                exc_info=True,
            )
            return False

    async def send_password_changed_alert(
        self, user: User, ip_address: Optional[str] = None
    ) -> bool:
        """Send password changed alert email.

        Args:
            user: User whose password was changed
            ip_address: IP address where change was made

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": "your password was changed",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": False,  # Always ask for confirmation
                "security_url": f"{self.settings.frontend_base_url}/auth/forgot-password",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"Your {self.settings.company_name} password was changed",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="password_changed",
                user_id=user.id,
                exc_info=True,
            )
            return False

    async def send_email_changed_alert(
        self,
        old_email: str,
        new_email: str,
        user_name: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> bool:
        """Send email changed alert to BOTH old and new addresses.

        Args:
            old_email: Previous email address
            new_email: New email address
            user_name: User's name
            ip_address: IP address where change was made

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user_name or old_email.split("@")[0],
                "alert_type": f"your email was changed from {old_email} to {new_email}",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": False,  # Always ask for confirmation
                "security_url": f"{self.settings.frontend_base_url}/admin",
                "company_name": self.settings.company_name,
            }

            # Send to old email
            result1 = await self.email_service.send_template(
                to=[old_email],
                subject=f"Your {self.settings.company_name} email was changed",
                template_name="security_alert",
                context=context,
            )

            # Send to new email
            result2 = await self.email_service.send_template(
                to=[new_email],
                subject=f"Your {self.settings.company_name} email was changed",
                template_name="security_alert",
                context=context,
            )

            return result1.success and result2.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="email_changed",
                user_id=None,
                exc_info=True,
            )
            return False

    async def send_mfa_enabled_alert(self, user: User, ip_address: Optional[str] = None) -> bool:
        """Send MFA enabled alert email.

        Args:
            user: User who enabled MFA
            ip_address: IP address where MFA was enabled

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": "Two-Factor Authentication (MFA) was enabled on your account",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": True,  # Assume it's them since they just did it
                "security_url": f"{self.settings.frontend_base_url}/admin",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"MFA enabled on your {self.settings.company_name} account",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="mfa_enabled",
                user_id=user.id,
                exc_info=True,
            )
            return False

    async def send_mfa_disabled_alert(self, user: User, ip_address: Optional[str] = None) -> bool:
        """Send MFA disabled alert email.

        Args:
            user: User who disabled MFA
            ip_address: IP address where MFA was disabled

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": "Two-Factor Authentication (MFA) was disabled on your account",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": False,  # Always ask for confirmation
                "security_url": f"{self.settings.frontend_base_url}/admin",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"MFA disabled on your {self.settings.company_name} account",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="mfa_disabled",
                user_id=user.id,
                exc_info=True,
            )
            return False

    async def send_api_key_created_alert(
        self, user: User, key_name: str, ip_address: Optional[str] = None
    ) -> bool:
        """Send API key created alert email.

        Args:
            user: User who created the API key
            key_name: Name of the API key
            ip_address: IP address where key was created

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": f"a new API key '{key_name}' was created",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": True,  # Assume it's them since they just did it
                "security_url": f"{self.settings.frontend_base_url}/admin/api-keys",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"New API key created on your {self.settings.company_name} account",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="api_key_created",
                user_id=user.id,
                exc_info=True,
            )
            return False

    async def send_account_locked_alert(
        self,
        user: User,
        reason: str = "too many failed login attempts",
        ip_address: Optional[str] = None,
    ) -> bool:
        """Send account locked alert email.

        Args:
            user: User whose account was locked
            reason: Reason for lockout
            ip_address: IP address of failed attempts

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            context = {
                "user_name": user.first_name or user.email.split("@")[0],
                "alert_type": f"your account was locked due to {reason}",
                "timestamp": utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "ip_address": ip_address,
                "was_you": False,  # Always ask for confirmation
                "security_url": f"{self.settings.frontend_base_url}/auth/forgot-password",
                "company_name": self.settings.company_name,
            }

            result = await self.email_service.send_template(
                to=[user.email],
                subject=f"Your {self.settings.company_name} account was locked",
                template_name="security_alert",
                context=context,
            )
            return result.success
        except Exception:
            _email_log.warning(
                "send_email_failed",
                template="security_alert",
                alert_type="account_locked",
                user_id=user.id,
                exc_info=True,
            )
            return False
