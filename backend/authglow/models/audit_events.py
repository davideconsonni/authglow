"""Audit event type enumeration.

Centralized, type-safe event taxonomy for audit logging.
All event types used across the application should be defined here.
"""

from enum import Enum


class AuditEventType(str, Enum):
    """Audit event types organized by category.

    Categories:
    - auth: Authentication & session events
    - lifecycle: User lifecycle & profile events
    - mfa: MFA, passkeys, trusted devices
    - oauth2: OAuth2/OIDC protocol events
    - admin: Admin actions (privilege escalation)
    - api_key: API key lifecycle
    - security: Security & anomaly detection
    - federation: Federated identity / SSO
    """

    # ============================================================
    # auth: Authentication & Session
    # ============================================================
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"

    # ============================================================
    # lifecycle: User Lifecycle & Profile
    # ============================================================
    USER_REGISTERED = "user_registered"
    USER_INVITED = "user_invited"
    EMAIL_VERIFICATION_SENT = "email_verification_sent"
    EMAIL_VERIFIED = "email_verified"
    EMAIL_CHANGED = "email_changed"
    PROFILE_UPDATED = "profile_updated"
    PASSWORD_CHANGED = "password_changed"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    PASSWORD_EXPIRED = "password_expired"
    ACCOUNT_DELETED = "account_deleted"

    # ============================================================
    # mfa: MFA, Passkeys, Trusted Devices
    # ============================================================
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    MFA_VERIFIED = "mfa_verified"
    MFA_FAILED = "mfa_failed"
    BACKUP_CODES_GENERATED = "backup_codes_generated"
    BACKUP_CODE_USED = "backup_code_used"
    BACKUP_CODE_FAILED = "backup_code_failed"
    PASSKEY_REGISTERED = "passkey_registered"
    PASSKEY_AUTHENTICATED = "passkey_authenticated"
    PASSKEY_DELETED = "passkey_deleted"
    TRUSTED_DEVICE_ADDED = "trusted_device_added"
    TRUSTED_DEVICE_REMOVED = "trusted_device_removed"
    TRUSTED_DEVICE_EXPIRED = "trusted_device_expired"

    # ============================================================
    # oauth2: OAuth2/OIDC Protocol Events
    # ============================================================
    AUTHORIZATION_CODE_ISSUED = "authorization_code_issued"
    AUTHORIZATION_CODE_REDEEMED = "authorization_code_redeemed"
    ACCESS_TOKEN_ISSUED = "access_token_issued"
    ACCESS_TOKEN_REFRESHED = "access_token_refreshed"
    ID_TOKEN_ISSUED = "id_token_issued"
    REFRESH_TOKEN_ISSUED = "refresh_token_issued"
    REFRESH_TOKEN_ROTATED = "refresh_token_rotated"
    ACCESS_TOKEN_REVOKED = "access_token_revoked"
    REFRESH_TOKEN_REVOKED = "refresh_token_revoked"
    TOKEN_INTROSPECTED = "token_introspected"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    CONSENT_UPDATED = "consent_updated"
    DEVICE_CODE_CREATED = "device_code_created"
    DEVICE_CODE_AUTHORIZED = "device_code_authorized"
    DEVICE_CODE_DENIED = "device_code_denied"
    DEVICE_CODE_EXPIRED = "device_code_expired"
    CLIENT_CREDENTIALS_TOKEN_ISSUED = "client_credentials_token_issued"

    # ============================================================
    # admin: Admin Actions (Privilege Escalation)
    # ============================================================
    ADMIN_USER_CREATED = "admin_user_created"
    ADMIN_USER_UPDATED = "admin_user_updated"
    ADMIN_USER_DELETED = "admin_user_deleted"
    ADMIN_PASSWORD_RESET = "admin_password_reset"
    ADMIN_SCOPE_ASSIGNED = "admin_scope_assigned"
    ADMIN_SCOPE_REMOVED = "admin_scope_removed"
    ADMIN_MFA_RESET = "admin_mfa_reset"
    ADMIN_CONSENT_REVOKED = "admin_consent_revoked"
    ADMIN_TOKEN_REVOKED = "admin_token_revoked"
    ADMIN_ROLE_ASSIGNED = "admin_role_assigned"
    ADMIN_ROLE_REMOVED = "admin_role_removed"

    # ============================================================
    # api_key: API Key Lifecycle
    # ============================================================
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_ROTATED = "api_key_rotated"
    API_KEY_EXPIRED = "api_key_expired"

    # ============================================================
    # security: Security & Anomaly Detection
    # ============================================================
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONCURRENT_SESSION_LIMIT_EXCEEDED = "concurrent_session_limit_exceeded"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    # ============================================================
    # federation: Federated Identity / SSO
    # ============================================================
    FEDERATED_LOGIN_INITIATED = "federated_login_initiated"
    FEDERATED_LOGIN_SUCCESS = "federated_login_success"
    FEDERATED_LOGIN_FAILED = "federated_login_failed"
    FEDERATED_ACCOUNT_LINKED = "federated_account_linked"
    FEDERATED_ACCOUNT_UNLINKED = "federated_account_unlinked"

    @property
    def category(self) -> str:
        """Return the event category for this event type."""
        if self.value.startswith("login_") or self.value in {
            "logout",
            "session_created",
            "session_revoked",
            "account_locked",
            "account_unlocked",
        }:
            return "auth"
        if self.value.startswith("user_") or self.value.startswith("email_") or self.value.startswith("profile_") or self.value.startswith("password_") or self.value == "account_deleted":
            return "lifecycle"
        if self.value.startswith("mfa_") or self.value.startswith("backup_code_") or self.value.startswith("passkey_") or self.value.startswith("trusted_device_"):
            return "mfa"
        if self.value.startswith("authorization_code_") or self.value.startswith("access_token_") or self.value.startswith("id_token_") or self.value.startswith("refresh_token_") or self.value in {
            "token_introspected",
            "consent_granted",
            "consent_revoked",
            "consent_updated",
            "device_code_created",
            "device_code_authorized",
            "device_code_denied",
            "device_code_expired",
            "client_credentials_token_issued",
        }:
            return "oauth2"
        if self.value.startswith("admin_"):
            return "admin"
        if self.value.startswith("api_key_"):
            return "api_key"
        if self.value in {
            "brute_force_detected",
            "suspicious_activity",
            "concurrent_session_limit_exceeded",
            "rate_limit_exceeded",
        }:
            return "security"
        if self.value.startswith("federated_"):
            return "federation"
        return "unknown"

    @property
    def default_severity(self) -> str:
        """Return default severity for this event type."""
        critical_events = {
            "account_locked",
            "brute_force_detected",
            "suspicious_activity",
            "admin_user_deleted",
            "admin_token_revoked",
            "admin_mfa_reset",
            "api_key_revoked",
        }
        warning_events = {
            "login_failed",
            "mfa_failed",
            "backup_code_failed",
            "federated_login_failed",
            "authorization_code_redeemed",  # could be replay
            "refresh_token_rotated",  # rotation is sensitive
            "api_key_rotated",  # rotation is sensitive
            "access_token_revoked",
            "refresh_token_revoked",
            "consent_revoked",
            "admin_user_updated",
            "admin_scope_removed",
            "admin_role_removed",
            "rate_limit_exceeded",
            "concurrent_session_limit_exceeded",
        }
        if self.value in critical_events:
            return "critical"
        if self.value in warning_events:
            return "warning"
        if self.value in {"logout", "session_revoked", "account_deleted"}:
            return "warning"
        return "info"
