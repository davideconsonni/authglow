# M8 - Add Unit Tests - Implementation Plan

## Overview
Currently 235 tests exist. Adding ~150 new tests across 13 new files + 2 extensions to bring coverage to security-critical and high-priority untested modules.

## Phase 1: Security-Critical (P0) - 7 new test files

### 1. `tests/unit/test_session.py` — SessionService
- Test create_mfa_session (returns MFASession, 5-min TTL, stores file)
- Test get_mfa_session (valid, expired auto-delete, not found)
- Test delete_mfa_session (exists, not found)
- Test create_consent_session (returns dict, 10-min TTL, uses secrets.token_urlsafe)
- Test get_consent_session (valid, expired auto-delete, not found)
- Test delete_consent_session (exists, not found)

### 2. `tests/unit/test_password_reset_service.py` — PasswordResetService
- Test create_reset_token (returns token + plaintext, stores file, bcrypt hash)
- Test verify_token (valid, wrong token, used token, expired token)
- Test mark_token_used (first use succeeds, double use fails, not found)
- Test get_token (exists, not found)
- Test list_user_tokens (by user, active_only filter)
- Test list_all_tokens (pagination)
- Test revoke_user_tokens (revokes all active)
- Test cleanup_expired_tokens (deletes used + expired >24h)
- Test get_stats (total/active/expired/used)

### 3. `tests/unit/test_oauth_client_service.py` — OAuth2ClientStorage
- Test create_client (hashes secret, stores file)
- Test get_client (exists, not found)
- Test update_client
- Test delete_client (exists, not found)
- Test list_clients (all, active_only, pagination)
- Test verify_client_secret (correct, wrong, inactive client)
- Test verify_redirect_uri (valid, invalid, inactive client)
- Test update_last_used
- Test rotate_secret (new secret works, old doesn't, not found raises)
- Test generate_client_secret (secure random)
- Test is_scope_allowed (all present, missing scope, inactive)
- Test is_grant_type_allowed (allowed, not allowed, inactive)

### 4. `tests/unit/test_oauth_consent_service.py` — OAuth2ConsentService
- Test create_consent (stores data, returns OAuth2Consent)
- Test get_consent (exists, not found)
- Test get_user_consent (found, expired auto-delete, revoked skipped)
- Test check_consent (all scopes present, missing scope, no consent)
- Test revoke_consent (success, not found, uses lock)
- Test revoke_user_client_consent (success, no consent)
- Test list_user_consents (sorted by granted_at desc)
- Test cleanup_expired_consents (deletes expired, keeps active)

### 5. `tests/unit/test_email_verification.py` — EmailVerificationService
- Test create_verification_token (stores file, uses secrets.token_urlsafe)
- Test get_token (exists, not found, corrupted file)
- Test mark_token_used (first use succeeds, double use fails, CAS protection)
- Test verify_email (valid token, invalid, used, expired, user not found)
- Test resend_verification_email (success, already verified, user not found)
- Test cleanup_expired_tokens (deletes expired)

### 6. `tests/unit/test_rbac.py` — RBACService
- Test create_permission/get_permission/get_permission_by_name
- Test list_permissions (sorted)
- Test delete_permission
- Test create_role/get_role/get_role_by_name
- Test list_roles (sorted)
- Test update_role (sets updated_at, uses lock)
- Test delete_role (prevents system role deletion)
- Test assign_role_to_user/remove_role_from_user
- Test get_user_roles (filters expired)
- Test get_user_permissions (aggregates from all roles)
- Test user_has_permission/user_has_role
- Test initialize_defaults (creates 11 permissions + 3 roles, idempotent)

### 7. `tests/unit/test_user_profile.py` — UserProfileService
- Test get_user_profile (found, not found, includes preferences)
- Test update_user_profile (updates fields, not found)
- Test change_password (success, wrong current password, user not found)
- Test change_email (success, email already in use, wrong password)
- Test delete_account (success, wrong confirmation, wrong password)
- Test get_user_preferences (exists, not found returns defaults)
- Test update_user_preferences (create, update)
- Test deactivate_account/reactivate_account

## Phase 2: High Priority (P1) - 3 new + 1 extension

### 8. `tests/unit/test_core_password.py` — core/password.py
- Test validate_password_strength (too short, too long, no letter, no digit/special, valid)
- Test calculate_password_strength (0: empty, 1: min 8, 2: 12+ chars, 3: 16+ chars or variety, etc.)

### 9. `tests/unit/test_security_notifications.py` — SecurityNotificationService
- Test send_login_alert (success, exception returns False)
- Test send_password_changed_alert (was_you=False, success)
- Test send_email_changed_alert (sends to both, returns True only if both succeed)
- Test send_mfa_enabled_alert (was_you=True)
- Test send_mfa_disabled_alert (was_you=False)
- Test send_api_key_created_alert (was_you=True)
- Test send_account_locked_alert (default reason, custom reason)

### 10. `tests/unit/test_oidc.py` — OIDCService
- Test get_user_info (openid scope → sub only, profile, email, phone, permissions, not found)
- Test build_user_claims (per-scope filtering)
- Test filter_claims_by_scopes (exact mapping from SCOPE_TO_CLAIMS)

### 11. Extend `tests/unit/test_permissions.py` — PermissionChecker
- Test PermissionChecker with admin scope bypass
- Test require_all_permissions=True (missing some, all present)
- Test require_all_permissions=False (at least one)
- Test require_all_roles similar
- Test get_current_user (valid token, invalid token, missing sub)
- Test require_permission/require_role helper functions

## Phase 3: Medium Priority (P2) - 1 new + extensions

### 12. `tests/unit/test_email_subsystem.py`
- Test EmailTemplateRenderer (render_template, render_both, auto-extension)
- Test ConsoleEmailProvider (send, validate_config True, get_provider_name)
- Test FileStorageEmailProvider (send, validate_config, get_provider_name)
- Test EmailService (send with template, send_template, validate_config)
- Test create_email_provider (file_storage, console default)
- Test get_email_service (cached singleton)

### 13. Extensions to existing test files
- test_audit.py: get_event_counts_by_type, get_logs_by_date
- test_api_key.py: get_key, get_user_keys, record_usage, cleanup_expired_keys
- test_oauth2.py: delete_authorization_code, verify_scopes, verify_grant_type
- test_jwt.py: decode_id_token
- test_refresh_token.py: get_refresh_token_by_id, cleanup_expired_tokens
- test_mfa.py: cleanup_expired_devices
- test_storage.py: update_last_login

## New Fixtures in conftest.py
Add fixtures for: session_service, password_reset_service, oauth_client_storage, oauth_consent_service, email_verification_service, rbac_service, user_profile_service, oidc_service

## Test Count Estimate
- Phase 1: ~90 tests
- Phase 2: ~35 tests
- Phase 3: ~25 tests
- Total new: ~150 tests
- Expected final count: ~385 tests