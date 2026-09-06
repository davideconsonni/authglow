"""Typed metadata schemas for audit log entries.

Each event category has its own metadata schema for structured,
validated logging. Use these models when calling AuditService.log_event()
to ensure consistent, queryable metadata.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BaseAuditMetadata(BaseModel):
    """Base class for all audit metadata.

    Provides common configuration and ensures extra fields are allowed
    for extensibility while maintaining validation on known fields.
    """

    model_config = ConfigDict(extra="allow")

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for audit logging."""
        return self.model_dump(mode="json", exclude_none=True)


# ============================================================
# Authentication & Session Metadata
# ============================================================

class AuthMetadata(BaseAuditMetadata):
    """Base metadata for authentication events."""

    auth_method: Optional[str] = None  # password, mfa, passkey, federated, device_code
    mfa_used: bool = False
    device_trusted: bool = False
    client_id: Optional[str] = None


class LoginSuccessMetadata(AuthMetadata):
    """Metadata for successful login."""

    auth_method: str  # Required for success
    session_id: Optional[str] = None
    refresh_token_id: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)


class LoginFailedMetadata(AuthMetadata):
    """Metadata for failed login."""

    failure_reason: str  # invalid_credentials, account_locked, mfa_required, mfa_failed, etc.
    failed_attempts_count: Optional[int] = None
    lockout_triggered: bool = False


class LogoutMetadata(AuthMetadata):
    """Metadata for logout."""

    logout_type: str = "user"  # user, admin, expired, security
    session_id: Optional[str] = None
    sessions_remaining: Optional[int] = None


class SessionMetadata(BaseAuditMetadata):
    """Metadata for session events."""

    session_id: str
    expires_at: Optional[datetime] = None
    refresh_token_id: Optional[str] = None
    client_id: Optional[str] = None


class AccountLockMetadata(BaseAuditMetadata):
    """Metadata for account lock/unlock."""

    lockout_reason: str  # brute_force, admin, suspicious_activity
    locked_until: Optional[datetime] = None
    failed_count: Optional[int] = None
    locked_by: Optional[str] = None  # user_id of admin who locked


# ============================================================
# User Lifecycle & Profile Metadata
# ============================================================

class LifecycleMetadata(BaseAuditMetadata):
    """Base metadata for lifecycle events."""

    changed_by: Optional[str] = None  # user_id of actor (self or admin)
    actor_type: str = "user"  # user, admin, system


class UserRegisteredMetadata(LifecycleMetadata):
    """Metadata for user registration."""

    registration_method: str  # self, admin, invite_accept
    invited_by: Optional[str] = None
    email_verified: bool = False
    scopes: List[str] = Field(default_factory=list)


class UserInvitedMetadata(LifecycleMetadata):
    """Metadata for user invitation."""

    invited_by: str  # Required
    scopes: List[str] = Field(default_factory=list)
    expires_at: Optional[datetime] = None


class EmailVerificationMetadata(LifecycleMetadata):
    """Metadata for email verification events."""

    verification_method: str = "link"  # link, code
    verification_token_id: Optional[str] = None


class EmailChangedMetadata(LifecycleMetadata):
    """Metadata for email change."""

    old_email_hash: str  # Hashed for PII protection
    new_email_hash: str
    verification_required: bool = True


class ProfileUpdatedMetadata(LifecycleMetadata):
    """Metadata for profile update."""

    fields_changed: List[str]
    old_values_hash: Optional[Dict[str, str]] = None  # Hashed for PII


class PasswordMetadata(LifecycleMetadata):
    """Base metadata for password events."""

    method: str  # current_password, admin_reset, reset_token
    password_policy_version: Optional[str] = None


class PasswordChangedMetadata(PasswordMetadata):
    """Metadata for password change."""

    require_change_on_next_login: bool = False


class PasswordResetMetadata(PasswordMetadata):
    """Metadata for password reset request/completion."""

    reset_token_id: Optional[str] = None
    expires_at: Optional[datetime] = None


class AccountDeletedMetadata(LifecycleMetadata):
    """Metadata for account deletion."""

    deletion_reason: str  # user_request, admin, gdpr_erasure, policy_violation
    gdpr_erasure: bool = False
    data_exported: bool = False


# ============================================================
# MFA, Passkeys, Trusted Devices Metadata
# ============================================================

class MFAMetadata(BaseAuditMetadata):
    """Base metadata for MFA events."""

    method: str  # totp, backup_code, passkey
    device_trusted: bool = False


class MFAEnabledMetadata(MFAMetadata):
    """Metadata for MFA enablement."""

    backup_codes_generated: int = 0
    totp_secret_id: Optional[str] = None


class MFAVerifiedMetadata(MFAMetadata):
    """Metadata for MFA verification."""

    challenge_id: Optional[str] = None


class MFAFailedMetadata(MFAMetadata):
    """Metadata for MFA failure."""

    failure_reason: str  # invalid_code, expired, locked, rate_limited
    failed_attempts: Optional[int] = None


class BackupCodeMetadata(MFAMetadata):
    """Metadata for backup code events."""

    codes_remaining: Optional[int] = None
    used_code_index: Optional[int] = None


class PasskeyMetadata(BaseAuditMetadata):
    """Base metadata for passkey events."""

    credential_id: Optional[str] = None
    aaguid: Optional[str] = None
    transports: List[str] = Field(default_factory=list)
    user_verification: Optional[str] = None  # required, preferred, discouraged


class PasskeyRegisteredMetadata(PasskeyMetadata):
    """Metadata for passkey registration."""

    attestation_type: Optional[str] = None  # none, indirect, direct
    attestation_statement: Optional[Dict[str, Any]] = None


class PasskeyRegistrationFailedMetadata(PasskeyMetadata):
    """Metadata for failed passkey registration."""

    error_class: str
    error: str
    success: bool = False


class PasskeyAuthenticatedMetadata(PasskeyMetadata):
    """Metadata for passkey authentication."""

    sign_count: int
    client_data_hash: Optional[str] = None


class TrustedDeviceMetadata(BaseAuditMetadata):
    """Metadata for trusted device events."""

    device_fingerprint: str
    device_name: Optional[str] = None
    expires_at: Optional[datetime] = None


# ============================================================
# OAuth2/OIDC Protocol Metadata
# ============================================================

class OAuth2BaseMetadata(BaseAuditMetadata):
    """Base metadata for OAuth2 events."""

    client_id: str
    grant_type: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)


class AuthorizationCodeMetadata(OAuth2BaseMetadata):
    """Metadata for authorization code events."""

    code_id: str
    redirect_uri: str
    pkce_method: Optional[str] = None  # S256, plain
    pkce_verified: bool = False
    nonce: Optional[str] = None
    acr_values: List[str] = Field(default_factory=list)
    response_type: str = "code"
    response_mode: Optional[str] = None
    auth_time: Optional[datetime] = None
    amr: List[str] = Field(default_factory=list)  # Authentication Methods References


class TokenIssuedMetadata(OAuth2BaseMetadata):
    """Metadata for token issuance (access, refresh, ID)."""

    token_id: str
    token_type: str  # access, refresh, id
    expires_in: int
    dpop_bound: bool = False
    dpop_jkt: Optional[str] = None  # JWK thumbprint for DPoP
    auth_code_id: Optional[str] = None  # Correlation to auth code
    auth_time: Optional[datetime] = None
    amr: List[str] = Field(default_factory=list)


class TokenRefreshedMetadata(OAuth2BaseMetadata):
    """Metadata for token refresh."""

    old_token_id: str
    new_token_id: str
    refresh_token_family_id: Optional[str] = None
    rotation: bool = True
    reused: bool = False  # True if reuse detected (security event)


class TokenRevokedMetadata(OAuth2BaseMetadata):
    """Metadata for token revocation."""

    token_id: str
    token_type_hint: Optional[str] = None  # access_token, refresh_token
    revoked_by: str  # user_id or "admin"
    revocation_reason: Optional[str] = None


class TokenIntrospectedMetadata(OAuth2BaseMetadata):
    """Metadata for token introspection."""

    token_id: str
    active: bool
    token_type: Optional[str] = None


class ConsentMetadata(OAuth2BaseMetadata):
    """Metadata for consent events."""

    consent_id: str
    granted_by: str  # user_id


class DeviceCodeMetadata(OAuth2BaseMetadata):
    """Metadata for device authorization events."""

    device_code_id: str
    user_code: str
    expires_in: int
    interval: int
    authorized_by: Optional[str] = None  # user_id who authorized


class ClientCredentialsMetadata(OAuth2BaseMetadata):
    """Metadata for client credentials grant."""

    client_auth_method: str  # client_secret_basic, client_secret_post, private_key_jwt, client_secret_jwt


# ============================================================
# Admin Actions Metadata
# ============================================================

class AdminActionMetadata(BaseAuditMetadata):
    """Base metadata for admin actions."""

    target_user_id: str
    target_user_email_hash: str
    admin_user_id: str
    admin_user_email_hash: str


class AdminUserMetadata(AdminActionMetadata):
    """Metadata for admin user CRUD."""

    fields_changed: Optional[List[str]] = None
    old_values_hash: Optional[Dict[str, str]] = None


class AdminPasswordResetMetadata(AdminActionMetadata):
    """Metadata for admin password reset."""

    require_change: bool = True
    temporary_password: bool = False


class AdminScopeMetadata(AdminActionMetadata):
    """Metadata for admin scope assignment/removal."""

    scopes: List[str]


class AdminMFAResetMetadata(AdminActionMetadata):
    """Metadata for admin MFA reset."""

    methods_cleared: List[str]  # totp, backup_codes, passkeys
    backup_codes_cleared: bool = False


class AdminConsentRevokedMetadata(AdminActionMetadata):
    """Metadata for admin consent revocation."""

    consent_id: str
    client_id: str


class AdminTokenRevokedMetadata(AdminActionMetadata):
    """Metadata for admin token revocation."""

    token_id: str
    token_type: str  # access_token, refresh_token
    target_user_id: str


class AdminRoleMetadata(AdminActionMetadata):
    """Metadata for admin role assignment/removal."""

    role: str


# ============================================================
# API Key Metadata
# ============================================================

class APIKeyMetadata(BaseAuditMetadata):
    """Base metadata for API key events."""

    key_id: str
    key_name: str
    scopes: List[str] = Field(default_factory=list)
    created_by: Optional[str] = None


class APIKeyCreatedMetadata(APIKeyMetadata):
    """Metadata for API key creation."""

    expires_at: Optional[datetime] = None


class APIKeyUsedMetadata(APIKeyMetadata):
    """Metadata for API key usage (sampled)."""

    client_ip_prefix: Optional[str] = None
    endpoint: Optional[str] = None
    user_agent_truncated: Optional[str] = None


class APIKeyRevokedMetadata(APIKeyMetadata):
    """Metadata for API key revocation."""

    revoked_by: str
    revocation_reason: Optional[str] = None


class APIKeyRotatedMetadata(APIKeyMetadata):
    """Metadata for API key rotation."""

    revoked_by: str
    revocation_reason: Optional[str] = None
    new_key_id: Optional[str] = None


# ============================================================
# Security & Anomaly Metadata
# ============================================================

class SecurityEventMetadata(BaseAuditMetadata):
    """Base metadata for security events."""

    risk_score: Optional[int] = None  # 0-100
    source_ip_prefix: Optional[str] = None
    user_agent_truncated: Optional[str] = None


class BruteForceMetadata(SecurityEventMetadata):
    """Metadata for brute force detection."""

    endpoint: str
    attempt_count: int
    window_seconds: int
    lockout_triggered: bool = False


class SuspiciousActivityMetadata(SecurityEventMetadata):
    """Metadata for suspicious activity."""

    anomaly_type: str  # impossible_travel, new_device, new_location, credential_stuffing
    details: Dict[str, Any] = Field(default_factory=dict)
    geo_distance_km: Optional[float] = None
    time_since_last_event_seconds: Optional[int] = None


class ConcurrentSessionMetadata(SecurityEventMetadata):
    """Metadata for concurrent session limit."""

    current_count: int
    limit: int
    action_taken: str  # revoked_oldest, denied_new, warned


class RateLimitExceededMetadata(SecurityEventMetadata):
    """Metadata for rate limit exceeded."""

    endpoint: str
    limit: int
    window_seconds: int
    retry_after_seconds: Optional[int] = None


# ============================================================
# Federation Metadata
# ============================================================

class FederationMetadata(BaseAuditMetadata):
    """Base metadata for federated identity events."""

    provider: str  # google, github, microsoft, saml, oidc
    provider_subject: str  # Subject identifier at provider
    client_id: Optional[str] = None


class FederatedLoginMetadata(FederationMetadata):
    """Metadata for federated login."""

    email_verified: bool = False
    provider_claims_hash: Optional[str] = None  # Hashed claims for audit
    failure_reason: Optional[str] = None


class FederatedAccountLinkedMetadata(FederationMetadata):
    """Metadata for federated account linking."""

    linked_by: str  # user_id
    existing_user_id: Optional[str] = None


# ============================================================
# Metadata Registry for Validation
# ============================================================

# Maps event_type to metadata schema for validation
METADATA_SCHEMAS: Dict[str, type[BaseAuditMetadata]] = {
    # Auth
    "login_success": LoginSuccessMetadata,
    "login_failed": LoginFailedMetadata,
    "logout": LogoutMetadata,
    "session_created": SessionMetadata,
    "session_revoked": SessionMetadata,
    "account_locked": AccountLockMetadata,
    "account_unlocked": AccountLockMetadata,
    # Lifecycle
    "user_registered": UserRegisteredMetadata,
    "user_invited": UserInvitedMetadata,
    "email_verification_sent": EmailVerificationMetadata,
    "email_verified": EmailVerificationMetadata,
    "email_changed": EmailChangedMetadata,
    "profile_updated": ProfileUpdatedMetadata,
    "password_changed": PasswordChangedMetadata,
    "password_reset_requested": PasswordResetMetadata,
    "password_reset_completed": PasswordResetMetadata,
    "password_expired": PasswordMetadata,
    "account_deleted": AccountDeletedMetadata,
    # MFA
    "mfa_enabled": MFAEnabledMetadata,
    "mfa_disabled": MFAMetadata,
    "mfa_verified": MFAVerifiedMetadata,
    "mfa_failed": MFAFailedMetadata,
    "backup_codes_generated": BackupCodeMetadata,
    "backup_code_used": BackupCodeMetadata,
    "backup_code_failed": BackupCodeMetadata,
    "passkey_registered": PasskeyRegisteredMetadata,
    "passkey_registration_failed": PasskeyRegistrationFailedMetadata,
    "passkey_authenticated": PasskeyAuthenticatedMetadata,
    "passkey_deleted": PasskeyMetadata,
    "trusted_device_added": TrustedDeviceMetadata,
    "trusted_device_removed": TrustedDeviceMetadata,
    "trusted_device_expired": TrustedDeviceMetadata,
    # OAuth2
    "authorization_code_issued": AuthorizationCodeMetadata,
    "authorization_code_redeemed": AuthorizationCodeMetadata,
    "access_token_issued": TokenIssuedMetadata,
    "access_token_refreshed": TokenRefreshedMetadata,
    "id_token_issued": TokenIssuedMetadata,
    "refresh_token_issued": TokenIssuedMetadata,
    "refresh_token_rotated": TokenRefreshedMetadata,
    "access_token_revoked": TokenRevokedMetadata,
    "refresh_token_revoked": TokenRevokedMetadata,
    "token_introspected": TokenIntrospectedMetadata,
    "consent_granted": ConsentMetadata,
    "consent_revoked": ConsentMetadata,
    "consent_updated": ConsentMetadata,
    "device_code_created": DeviceCodeMetadata,
    "device_code_authorized": DeviceCodeMetadata,
    "device_code_denied": DeviceCodeMetadata,
    "device_code_expired": DeviceCodeMetadata,
    "client_credentials_token_issued": ClientCredentialsMetadata,
    # Admin
    "admin_user_created": AdminUserMetadata,
    "admin_user_updated": AdminUserMetadata,
    "admin_user_deleted": AdminUserMetadata,
    "admin_password_reset": AdminPasswordResetMetadata,
    "admin_scope_assigned": AdminScopeMetadata,
    "admin_scope_removed": AdminScopeMetadata,
    "admin_mfa_reset": AdminMFAResetMetadata,
    "admin_consent_revoked": AdminConsentRevokedMetadata,
    "admin_token_revoked": AdminTokenRevokedMetadata,
    "admin_role_assigned": AdminRoleMetadata,
    "admin_role_removed": AdminRoleMetadata,
    # API Key
    "api_key_created": APIKeyCreatedMetadata,
    "api_key_used": APIKeyUsedMetadata,
    "api_key_revoked": APIKeyRevokedMetadata,
    "api_key_rotated": APIKeyRotatedMetadata,
    "api_key_expired": APIKeyMetadata,
    # Security
    "brute_force_detected": BruteForceMetadata,
    "suspicious_activity": SuspiciousActivityMetadata,
    "concurrent_session_limit_exceeded": ConcurrentSessionMetadata,
    "rate_limit_exceeded": RateLimitExceededMetadata,
    # Federation
    "federated_login_initiated": FederatedLoginMetadata,
    "federated_login_success": FederatedLoginMetadata,
    "federated_login_failed": FederatedLoginMetadata,
    "federated_account_linked": FederatedAccountLinkedMetadata,
    "federated_account_unlinked": FederatedAccountLinkedMetadata,
}


def get_metadata_schema(event_type: str) -> Optional[type[BaseAuditMetadata]]:
    """Get the metadata schema class for an event type.

    Returns None if no schema is defined (allows flexible metadata).
    """
    return METADATA_SCHEMAS.get(event_type)


def validate_metadata(event_type: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Validate metadata against schema for event type.

    Returns the validated metadata dict (with defaults applied).
    Raises ValidationError if metadata is invalid.
    Only validates when metadata is non-empty to allow optional metadata.
    """
    if not metadata:
        return metadata
    schema = get_metadata_schema(event_type)
    if schema is None:
        return metadata
    validated = schema(**metadata)
    return validated.to_dict()
