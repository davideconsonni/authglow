# Audit Logging Enhancement Plan — AuthGlow (2026-09-05)

> **Scope**: migliorare l'audit logging per tracciare **cosa fanno gli utenti** dell'applicazione in modo completo, strutturato e conforme OAuth2/OIDC.
> **Metodo**: analisi del codice corrente (`backend/authglow/services/audit.py`, `LoginHistoryService`, `AdminActionService`, endpoint API) — non solo documentazione.
> **Stato attuale**: fondazione solida (`AuditService` write-only, stdout JSON via structlog, PII masking, request_id correlation) ma copertura parziale degli eventi.

---

## Stato Corrente (Baseline)

| Componente              | File                        | Cosa fa                                                                                            | Gap principali                                                                         |
|-------------------------|-----------------------------|----------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| **AuditService**        | `services/audit.py`         | Write-only, structlog JSON, PII masking (hash/mask/none), IP truncation, UA truncation, request_id | Solo eventi espliciti chiamati; manca tassonomia centralizzata                         |
| **AuditLogEntry**       | `models/admin.py:142`       | Modello Pydantic per entry                                                                         | Campi limitati: no `session_id`, `client_id`, `correlation_id`, metadata tipizzati     |
| **LoginHistoryService** | `services/login_history.py` | Login attempts (success/fail), 90d retention                                                       | Solo login; non copre logout, session, MFA, passkey, federated                         |
| **AdminActionService**  | `services/admin_action.py`  | Azioni admin su utenti, 365d retention                                                             | Non usato da tutti gli endpoint admin                                                  |
| **OAuth2/OIDC Events**  | Sparsi                      | `oidc_logout`, `refresh_token_revoked_by_admin`                                                    | Mancano: auth code, token issuance/refresh/revoke, consent, device auth, introspection |

---

## Tassonomia Eventi Proposta (OAuth2/OIDC Compliant)

### A. Authentication & Session
| Event Type                            | Trigger                                        | Metadata Chiave                                               |
|---------------------------------------|------------------------------------------------|---------------------------------------------------------------|
| `login_success`                       | Password, MFA, passkey, federated, device_code | `auth_method`, `mfa_used`, `device_trusted`, `client_id`      |
| `login_failed`                        | Stesso + reason                                | `failure_reason`, `failed_attempts_count`                     |
| `logout`                              | User-initiated, admin revoke, session expiry   | `logout_type` (user/admin/expired), `session_count_remaining` |
| `session_created`                     | Post-login, refresh                            | `session_id`, `expires_at`, `refresh_token_id`                |
| `session_revoked`                     | Admin, user, security                          | `revocation_reason`, `revoked_by`                             |
| `account_locked` / `account_unlocked` | Brute force, admin                             | `lockout_reason`, `locked_until`, `failed_count`              |

### B. User Lifecycle & Profile
| Event Type                                                                   | Trigger                               | Metadata Chiave                                       |
|------------------------------------------------------------------------------|---------------------------------------|-------------------------------------------------------|
| `user_registered`                                                            | Self-reg, admin create, invite accept | `registration_method`, `invited_by`, `email_verified` |
| `user_invited`                                                               | Admin invite                          | `invited_by`, `scopes`, `expires_at`                  |
| `email_verification_sent` / `email_verified`                                 | Flow verifica                         | `verification_method` (link/code)                     |
| `email_changed`                                                              | User/admin                            | `old_email_hash`, `new_email_hash`, `changed_by`      |
| `profile_updated`                                                            | User/admin                            | `fields_changed`, `changed_by`                        |
| `password_changed` / `password_reset_requested` / `password_reset_completed` | User flow                             | `method` (current/admin/reset_token), `changed_by`    |
| `password_expired`                                                           | Policy                                | `expired_at`                                          |
| `account_deleted`                                                            | Self-service, admin, GDPR             | `deletion_reason`, `deleted_by`, `gdpr_erasure`       |

### C. MFA & Passkeys (Strong Auth)
| Event Type                                                                   | Trigger                  | Metadata Chiave                                              |
|------------------------------------------------------------------------------|--------------------------|--------------------------------------------------------------|
| `mfa_enabled` / `mfa_disabled`                                               | User TOTP enroll/disable | `method` (totp), `backup_codes_generated`                    |
| `mfa_verified` / `mfa_failed`                                                | Login step-up            | `method`, `failure_reason`                                   |
| `backup_codes_generated` / `backup_code_used` / `backup_code_failed`         | Backup codes             | `codes_remaining`, `used_code_index`                         |
| `passkey_registered` / `passkey_authenticated` / `passkey_deleted`           | WebAuthn                 | `credential_id`, `aaguid`, `transports`, `user_verification` |
| `trusted_device_added` / `trusted_device_removed` / `trusted_device_expired` | Device trust             | `device_fingerprint`, `device_name`, `expires_at`            |

### D. OAuth2/OIDC Protocol Events (CRITICAL for Compliance)
| Event Type                                                              | RFC Section            | Trigger                                    | Metadata Chiave                                                                        |
|-------------------------------------------------------------------------|------------------------|--------------------------------------------|----------------------------------------------------------------------------------------|
| `authorization_code_issued`                                             | RFC 6749 §4.1          | `/oauth2/authorize` consent                | `code_id`, `client_id`, `scopes`, `pkce_method`, `nonce`, `acr_values`, `redirect_uri` |
| `authorization_code_redeemed`                                           | RFC 6749 §4.1.3        | `/oauth2/token` (grant=auth_code)          | `code_id`, `client_id`, `pkce_verified`, `tokens_issued` (access/refresh/id)           |
| `access_token_issued`                                                   | RFC 6749 §5.1          | Token endpoint (all grants)                | `token_id`, `client_id`, `grant_type`, `scopes`, `expires_in`, `dpop_bound`            |
| `access_token_refreshed`                                                | RFC 6749 §6            | `/oauth2/token` (grant=refresh_token)      | `old_token_id`, `new_token_id`, `client_id`, `rotation`, `scopes`                      |
| `id_token_issued`                                                       | OIDC Core §3.1.3       | Token endpoint (openid scope)              | `token_id`, `client_id`, `auth_time`, `amr`, `nonce`                                   |
| `refresh_token_issued`                                                  | RFC 6749 §5.1          | Token endpoint (offline_access)            | `token_id`, `client_id`, `family_id`, `expires_in`                                     |
| `refresh_token_rotated`                                                 | RFC 6749 §6 + rotation | Refresh token exchange                     | `old_token_id`, `new_token_id`, `family_id`, `reused` (bool)                           |
| `access_token_revoked` / `refresh_token_revoked`                        | RFC 7009               | `/oauth2/revoke`                           | `token_id`, `client_id`, `revoked_by` (user/admin), `token_type_hint`                  |
| `token_introspected`                                                    | RFC 7662               | `/oauth2/introspect`                       | `token_id`, `client_id`, `active`                                                      |
| `consent_granted` / `consent_revoked` / `consent_updated`               | OIDC Core              | Consent page, admin                        | `consent_id`, `client_id`, `scopes`, `granted_by`                                      |
| `device_code_created`                                                   | RFC 8628 §3.1          | `/oauth2/device/authorize`                 | `device_code_id`, `client_id`, `scopes`, `expires_in`, `interval`                      |
| `device_code_authorized` / `device_code_denied` / `device_code_expired` | RFC 8628 §3.4          | User consent, timeout                      | `device_code_id`, `user_code`, `authorized_by`, `client_id`                            |
| `client_credentials_token_issued`                                       | RFC 6749 §4.4          | `/oauth2/token` (grant=client_credentials) | `token_id`, `client_id`, `scopes`, `auth_method`                                       |

### E. Admin Actions (Privilege Escalation)
| Event Type                                                         | Trigger            | Metadata Chiave                                                       |
|--------------------------------------------------------------------|--------------------|-----------------------------------------------------------------------|
| `admin_user_created` / `admin_user_updated` / `admin_user_deleted` | Admin API          | `target_user_id`, `target_email_hash`, `changed_by`, `fields_changed` |
| `admin_password_reset`                                             | Admin set-password | `target_user_id`, `require_change`, `reset_by`                        |
| `admin_scope_assigned` / `admin_scope_removed`                     | Admin scopes       | `target_user_id`, `scopes`, `changed_by`                              |
| `admin_mfa_reset`                                                  | Admin MFA disable  | `target_user_id`, `reset_by`, `methods_cleared`                       |
| `admin_consent_revoked`                                            | Admin consents     | `consent_id`, `client_id`, `revoked_by`                               |
| `admin_token_revoked`                                              | Admin tokens       | `token_id`, `target_user_id`, `revoked_by`                            |
| `admin_role_assigned` / `admin_role_removed`                       | RBAC               | `target_user_id`, `role`, `changed_by`                                |

### F. API Keys (Service-to-Service)
| Event Type                            | Trigger        | Metadata Chiave                                        |
|---------------------------------------|----------------|--------------------------------------------------------|
| `api_key_created`                     | Admin/user     | `key_id`, `name`, `scopes`, `expires_at`, `created_by` |
| `api_key_used`                        | Token exchange | `key_id`, `client_ip_prefix`, `endpoint` (sampled)     |
| `api_key_revoked` / `api_key_expired` | Admin, expiry  | `key_id`, `revoked_by`, `reason`                       |

### G. Security & Anomaly Detection
| Event Type                          | Trigger                           | Metadata Chiave                                    |
|-------------------------------------|-----------------------------------|----------------------------------------------------|
| `brute_force_detected`              | Rate limit exceeded               | `ip_prefix`, `endpoint`, `attempt_count`, `window` |
| `suspicious_activity`               | Impossible travel, new device/geo | `anomaly_type`, `risk_score`, `details`            |
| `concurrent_session_limit_exceeded` | Policy                            | `current_count`, `limit`, `action_taken`           |
| `rate_limit_exceeded`               | Auth endpoints                    | `endpoint`, `ip_prefix`, `limit`, `window`         |

### H. Federation (SSO)
| Event Type                                                | Trigger         | Metadata Chiave                                           |
|-----------------------------------------------------------|-----------------|-----------------------------------------------------------|
| `federated_login_initiated`                               | Redirect to IdP | `provider`, `client_id`, `scopes`                         |
| `federated_login_success` / `federated_login_failed`      | Callback        | `provider`, `subject`, `email_verified`, `failure_reason` |
| `federated_account_linked` / `federated_account_unlinked` | Account linking | `provider`, `subject`, `linked_by`                        |

---

## Modifiche al Modello Dati

### AuditLogEntry (estendere `models/admin.py`)
```python
class AuditLogEntry(BaseModel):
    id: str
    user_id: Optional[str] = None
    email: Optional[str] = None
    event_type: str                    # Da AuditEventType enum
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"             # info, warning, error, critical
    request_id: Optional[str] = None   # Correlation ID
    # NUOVI CAMPI:
    session_id: Optional[str] = None   # Per correlare eventi nella stessa sessione
    client_id: Optional[str] = None    # OAuth2 client_id quando applicabile
    correlation_id: Optional[str] = None  # Cross-request correlation (es. auth code -> token)
    event_category: str = "auth"       # auth, oauth2, admin, security, lifecycle, mfa, federation, api_key
```

### AuditEventType Enum (nuovo file `models/audit_events.py`)
```python
from enum import Enum

class AuditEventType(str, Enum):
    # Auth & Session
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    SESSION_CREATED = "session_created"
    SESSION_REVOKED = "session_revoked"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"

    # Lifecycle
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

    # MFA & Passkeys
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

    # OAuth2/OIDC
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

    # Admin
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

    # API Keys
    API_KEY_CREATED = "api_key_created"
    API_KEY_USED = "api_key_used"
    API_KEY_REVOKED = "api_key_revoked"
    API_KEY_EXPIRED = "api_key_expired"

    # Security
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONCURRENT_SESSION_LIMIT_EXCEEDED = "concurrent_session_limit_exceeded"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"

    # Federation
    FEDERATED_LOGIN_INITIATED = "federated_login_initiated"
    FEDERATED_LOGIN_SUCCESS = "federated_login_success"
    FEDERATED_LOGIN_FAILED = "federated_login_failed"
    FEDERATED_ACCOUNT_LINKED = "federated_account_linked"
    FEDERATED_ACCOUNT_UNLINKED = "federated_account_unlinked"
```

### Metadata Typed Schemas (nuovo file `models/audit_metadata.py`)
```python
# Esempio per OAuth2 token events
class OAuth2TokenMetadata(BaseModel):
    token_id: str
    client_id: str
    grant_type: str
    scopes: List[str]
    expires_in: int
    dpop_bound: bool = False
    token_type: str  # access, refresh, id

class AuthCodeMetadata(BaseModel):
    code_id: str
    client_id: str
    scopes: List[str]
    pkce_method: Optional[str] = None
    nonce: Optional[str] = None
    acr_values: Optional[List[str]] = None
    redirect_uri: str

class MFAMetadata(BaseModel):
    method: str  # totp, backup_code, passkey
    device_trusted: bool = False
    failure_reason: Optional[str] = None
```

---

## Configurazione Aggiuntiva (`core/config.py`)

```python
class Settings(BaseSettings):
    # ... existing ...

    # Audit configuration
    audit_enabled: bool = True
    audit_event_categories: List[str] = [
        "auth", "oauth2", "admin", "security",
        "lifecycle", "mfa", "federation", "api_key"
    ]
    audit_retention_days: Dict[str, int] = {
        "auth": 90,
        "oauth2": 90,
        "admin": 365,
        "security": 730,
        "lifecycle": 365,
        "mfa": 365,
        "federation": 365,
        "api_key": 365,
    }
    audit_sample_rate: float = 1.0  # Per eventi ad alto volume (es. token refresh)
    audit_log_level: str = "hash"   # none, mask, hash (VAPT-080: none vietato in prod)
```

---

## Integrazione nei Servizi Esistenti

### Pattern di Iniezione (già usato)
```python
# In ogni router/service che deve auditare
from authglow.services.audit import AuditService, get_audit_service
from fastapi import Depends

@router.post("/endpoint")
async def endpoint(
    ...,
    audit_service: AuditService = Depends(get_audit_service),
):
    await audit_service.log_event(
        event_type=AuditEventType.LOGIN_SUCCESS,
        user_id=user.id,
        email=user.email,
        client_id=client_id,  # quando applicabile
        session_id=session_id,
        correlation_id=correlation_id,
        metadata=OAuth2TokenMetadata(...).model_dump(),
        severity="info",
    )
```

### Mapping Servizio → Eventi da Aggiungere

| Servizio/Router                           | Eventi da Aggiungere                                                                                                                                                                  |
|-------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `api/auth.py:authorize_post`              | `authorization_code_issued`, `consent_granted`                                                                                                                                        |
| `api/auth.py:token_post`                  | `access_token_issued`, `refresh_token_issued`, `id_token_issued`, `authorization_code_redeemed`, `access_token_refreshed`, `refresh_token_rotated`, `client_credentials_token_issued` |
| `api/auth.py:refresh_post`                | `access_token_refreshed`, `refresh_token_rotated`                                                                                                                                     |
| `api/oauth2_advanced.py:revoke_token`     | `access_token_revoked`, `refresh_token_revoked`                                                                                                                                       |
| `api/oauth2_advanced.py:introspect_token` | `token_introspected`                                                                                                                                                                  |
| `api/oidc.py:logout_*`                    | `logout` (già fatto), `session_revoked`                                                                                                                                               |
| `api/device_auth.py`                      | `device_code_created`, `device_code_authorized/denied/expired`                                                                                                                        |
| `api/mfa.py`                              | `mfa_verified`, `mfa_failed`, `mfa_enabled/disabled`, `backup_code_*`                                                                                                                 |
| `api/passkey.py`                          | `passkey_registered/authenticated/deleted`, `trusted_device_*`                                                                                                                        |
| `api/federation.py`                       | `federated_login_*`, `federated_account_linked/unlinked`                                                                                                                              |
| `api/admin.py` (users)                    | `admin_user_*`, `admin_password_reset`, `admin_scope_*`, `admin_mfa_reset`, `admin_role_*`                                                                                            |
| `api/admin.py` (consents)                 | `admin_consent_revoked`                                                                                                                                                               |
| `api/admin.py` (tokens)                   | `admin_token_revoked`                                                                                                                                                                 |
| `services/api_key.py`                     | `api_key_created/used/revoked/expired`                                                                                                                                                |
| `services/user_profile.py`                | `email_changed`, `profile_updated`, `password_changed`, `account_deleted`                                                                                                             |
| `services/registration.py`                | `user_registered`, `email_verification_sent`                                                                                                                                          |
| `services/invitation.py`                  | `user_invited`                                                                                                                                                                        |

---

## Fasi di Implementazione

### Fase 1: Core Infrastructure (Foundation) ⏱️ ~2-3 giorni ✅ COMPLETATA
- [x] **1.1** Creare `AuditEventType` enum in `models/audit_events.py`
- [x] **1.2** Estendere `AuditLogEntry` con `session_id`, `client_id`, `correlation_id`, `event_category`
- [x] **1.3** Creare metadata schemas tipizzati in `models/audit_metadata.py`
- [x] **1.4** Aggiornare `AuditService.log_event()` per accettare enum + metadata tipizzati + validazione campi obbligatori per categoria
- [x] **1.5** Aggiungere config `audit_event_categories`, `audit_retention_days`, `audit_sample_rate` in `core/config.py`
- [x] **1.6** Test unitari per nuovi campi, enum, validazione metadata

### Fase 2: Authentication & Session Events ⏱️ ~2 giorni ✅ COMPLETATA
- [x] **2.1** `api/auth.py:authorize_post` → `authorization_code_issued`, `consent_granted`
- [x] **2.2** `api/auth.py:token_post` → `access_token_issued`, `refresh_token_issued`, `id_token_issued`, `authorization_code_redeemed`, `client_credentials_token_issued`
- [x] **2.3** `api/auth.py:refresh_post` (`cookie_refresh`) → `access_token_refreshed`, `refresh_token_rotated`
- [x] **2.4** `api/auth.py:cookie_logout` → `logout` con `session_id`
- [x] **2.4** `api/auth.py:register_user` → `user_registered`, `email_verification_sent`
- [x] **2.5** `services/user_profile.py` → `email_changed`, `profile_updated`, `password_changed`, `account_deleted` (+ `deactivate_account`, `reactivate_account`)
- [x] **2.6** `services/invitation.py` → `user_invited` (già presente in `invite_user` in `api/auth.py`)
- [ ] **2.7** Login history: integrare con `LoginHistoryService` per evitare duplicazione (delegare a quello per login success/failed) — *opzionale, architetturale*

### Fase 3: OAuth2/OIDC Protocol Events (Critical) ⏱️ ~3 giorni ✅ COMPLETATA
- [x] **3.1** `api/oauth2_advanced.py:revoke_token` → `access_token_revoked`, `refresh_token_revoked` (con `token_type_hint`)
- [x] **3.2** `api/oauth2_advanced.py:introspect_token` → `token_introspected`
- [x] **3.3** `api/device_auth.py` → `device_code_created`, `device_code_authorized`, `device_code_denied`, `device_code_expired`
- [x] **3.4** `api/admin.py:consents` → `admin_consent_revoked` + `consent_revoked` (user-initiated - non implementato nell'endpoint)
- [x] **3.5** PKCE verification logging in code redemption (già in `authorization_code_redeemed`)
- [x] **3.6** DPoP binding info in token metadata (già in `TokenIssuedMetadata`)

### Fase 4: MFA, Passkeys & Federation ⏱️ ~2 giorni
- [ ] **4.1** `api/mfa.py` → `mfa_verified`, `mfa_failed`, `mfa_enabled`, `mfa_disabled`, `backup_code_generated/used/failed`
- [ ] **4.2** `api/passkey.py` → `passkey_registered`, `passkey_authenticated`, `passkey_deleted`
- [ ] **4.3** `services/mfa.py` → `trusted_device_added/removed/expired`
- [ ] **4.4** `api/federation.py` → `federated_login_initiated/success/failed`, `federated_account_linked/unlinked`

### Fase 5: Admin Actions & API Keys ⏱️ ~2 giorni
- [ ] **5.1** Verificare tutti gli endpoint `api/admin.py` usano `AdminActionService` + `AuditService`
- [ ] **5.2** `services/api_key.py` → `api_key_created`, `api_key_used` (sampled), `api_key_revoked`, `api_key_expired`
- [ ] **5.3** RBAC events se presenti: `admin_role_assigned/removed`

### Fase 6: Security & Anomaly Events ⏱️ ~1-2 giorni
- [ ] **6.1** Rate limit middleware → `rate_limit_exceeded` (su auth endpoints)
- [ ] **6.2** Account lockout logic → `account_locked/unlocked`, `brute_force_detected`
- [ ] **6.3** Concurrent session limit → `concurrent_session_limit_exceeded`
- [ ] **6.4** Suspicious activity detection (new device/geo, impossible travel) → `suspicious_activity`

### Fase 7: Frontend Admin Audit UI ⏱️ ~3-4 giorni (separabile)
- [ ] **7.1** Nuovo endpoint `GET /api/admin/audit-logs` con filtri (user_id, event_type, category, severity, date range, client_id)
- [ ] **7.2** Pagina Admin `AdminAuditLogsPage.tsx` con tabella filtratile, sortable, export CSV/JSON
- [ ] **7.3** Dettaglio evento (modal) con metadata strutturato
- [ ] **7.4** Real-time alerts: webhook per eventi `critical` + `error` severity

### Fase 8: Testing, Hardening & Documentation ⏱️ ~2 giorni
- [ ] **8.1** Test integrazione per ogni categoria evento (flussi completi)
- [ ] **8.2** Property-based test per PII masking determinismo
- [ ] **8.3** Load test: audit logging <10ms p99, non blocca request path
- [ ] **8.4** Documentazione: `docs/audit-logging.md` con tassonomia, esempi JSON, configurazione retention
- [ ] **8.5** Aggiornare `ARCHITECTURE.md` con sezione Audit
- [ ] **8.6** Aggiornare `AGENTS.md` con linee guida audit logging
- [ ] **8.7** Aggiornare `README.md` se necessario (nuovi endpoint/feature)

---

## Dipendenze tra Fasi

```
Fase 1 (Core) ──────────┬──────────► Fase 2 (Auth) ──────► Fase 3 (OAuth2)
                        │                              │
                        ├──────────► Fase 4 (MFA/Fed) ──┤
                        │                              │
                        ├──────────► Fase 5 (Admin) ────┤
                        │                              │
                        └──────────► Fase 6 (Security) ─┘
                                                              │
                                               ┌──────────────┴──────────────┐
                                               ▼                             ▼
                                        Fase 7 (UI)                    Fase 8 (Test/Docs)
                                               │                             │
                                               └──────────────┬──────────────┘
                                                              ▼
                                                      COMPLETAMENTO
```

**Nota**: Fasi 2-6 possono procedere in parallelo dopo Fase 1 (dipendono solo da core infrastructure). Fase 7 e 8 sono dipendenti dal completamento delle fasi di backend.

---

## Testing Strategy

| Livello         | Cosa Testare                                                                                      | Strumenti             |
|-----------------|---------------------------------------------------------------------------------------------------|-----------------------|
| **Unit**        | `AuditService.log_event` con tutti gli enum, metadata validation, PII masking deterministico      | pytest, hypothesis    |
| **Integration** | Flussi completi: login→token→refresh→revoke, auth code flow, device auth, MFA, passkey, federated | pytest-asyncio, httpx |
| **Contract**    | Conformità RFC: event_type presenti per ogni sezione RFC                                          | Custom test suite     |
| **Performance** | p99 < 10ms per `log_event`, no blocking, sampling funziona                                        | locust/k6             |
| **Security**    | Nessun secret in log, PII masked correttamente, request_id propagato                              | Custom assertions     |

---

## Rollout & Compatibility

| Aspetto             | Strategia                                                                      |
|---------------------|--------------------------------------------------------------------------------|
| **Backward Compat** | `event_type` string invariati dove già usati; nuovi enum per nuovi eventi      |
| **Log Parsers**     | Aggiungere campi (non rimuovere); parser esistenti ignorano campi sconosciuti  |
| **Deployment**      | Feature flag `audit_enabled` per rollout graduale; default `true`              |
| **Sampling**        | `audit_sample_rate` per eventi ad alto volume (token refresh); default 1.0     |
| **Migration**       | Nessuna migrazione dati richiesta (write-only, nuovo formato per nuovi eventi) |

---

## Rischi & Mitigazioni

| Rischio                                                 | Probabilità | Impatto | Mitigazione                                                                        |
|---------------------------------------------------------|-------------|---------|------------------------------------------------------------------------------------|
| Performance degradation su token endpoint (alto volume) | Media       | Alto    | Sampling configurabile, async non-blocking, benchmark pre-deploy                   |
| Breaking change per log parsers esterni                 | Bassa       | Medio   | Solo campi additive, documentare changelog                                         |
| Event duplication (login history + audit)               | Media       | Basso   | Delegare login success/failed a `LoginHistoryService`, audit solo per eventi extra |
| PII leakage in metadata                                 | Bassa       | Critico | Test automatizzati per ogni nuovo metadata schema, code review obbligatorio        |
| Missing events per nuovi endpoint futuri                | Alta        | Medio   | Lint rule / PR checklist: "Hai aggiunto audit logging?"                            |

---

## Definizione di "Done" per Ogni Fase

- [ ] Tutti gli eventi della fase implementati e testati (unit + integration)
- [ ] Nessun test regresso rotto
- [ ] `ruff check` + `mypy` passano
- [ ] Documentazione aggiornata (se API pubblica cambia)
- [ ] Code review approvato

---

## Note per l'Agente Successivo

1. **Inizia da Fase 1** — è la fondazione; senza enum + metadata tipizzati le fasi successive sono inconsistenti
2. **Usa `codegraph_explore`** per trovare i punti esatti di integrazione prima di modificare
3. **Testa incrementalmente** — dopo ogni endpoint modificato, run test correlati
4. **Non duplicare** — `LoginHistoryService` esiste per login history; `AdminActionService` per admin actions. L'`AuditService` è per **eventi di sicurezza/compliance** cross-cutting
5. **Riferimenti chiave**:
   - `docs/plans/OAUTH2_OIDC_COMPLIANCE_PLAN.md` — per eventi OAuth2 obbligatori
   - `backend/tests/unit/test_audit.py` — pattern test esistenti
   - `backend/authglow/services/audit.py` — implementazione attuale
   - `backend/authglow/services/login_history.py` — pattern per persistence separata

---

## Changelog

- 2026-09-06: Fase 3 completata (oauth2_advanced: revoke_token, introspect_token; device_auth: device_code_created, device_code_authorized, device_code_denied, device_code_expired; admin: admin_consent_revoked). Fase 2 completata. Fase 1 completata.
- 2026-09-05: Creazione piano completo (Fasi 1-8), tassonomia eventi, modello dati, fasi, testing strategy
