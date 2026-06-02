# AuthGlow - Feature Catalog

> Complete feature catalog. This file serves as a single reference for regenerating documentation, frontend (React), and consent screens.  
> For implementation details, consult the source code (`authglow/api/`, `authglow/services/`, `authglow/models/`).

---

## 1. User Authentication & Lifecycle

### Public Registration
- Endpoint `POST /api/users` — self-registration with password validation
- Disableable via env `ALLOW_PUBLIC_REGISTRATION=false`
- Configurable password policy: minimum length, uppercase/lowercase/digits/special characters required
- On registration: verification email + welcome email sent
- Audit log: event `user_registered`

### Login
- **Traditional login**: `POST /api/token` (OAuth2PasswordRequestForm) with username/password
- **OAuth2 login**: `GET/POST /oauth2/authorize` → login form → redirect with authorization code
- Rate limiting: 5 attempts/minute on `/api/token`, 10/minute on `/oauth2/authorize`
- Automatic account lockout after 5 consecutive failed attempts (15 minutes, configurable)
- User enumeration protection: identical error messages for nonexistent email and wrong password
- Timing side-channel protection: random jitter in responses for users not found

### User Invitation (Admin)
- `POST /api/users/invite` — admin invites a new user
- Temporary password generation, welcome email with verification link
- Audit log: event `user_invited`

### Password Reset
- `POST /api/password/reset/request` — request reset (5/hour, anti-abuse)
- Always returns "success" to prevent email enumeration
- One-time token with 30-minute expiration
- `POST /api/password/reset/confirm` — set new password with validation
- Automatic revocation of user's pre-existing active tokens

### Password Change (authenticated user)
- `POST /api/password/change` — requires current password
- Prevents reuse of the same password
- `POST /api/profile/me/change-password` — alternative endpoint via profile

### Email Verification
- Verification email sent upon registration
- `GET /verify-email?token=...` — HTML confirmation page
- `POST /api/email/verify` — API verification
- `POST /api/email/resend-verification` — resend email (5/hour)
- `GET /resend-verification` — HTML page to request resend

### Account Lifecycle
- **Deactivation**: `POST /api/profile/me/deactivate` — account deactivated but recoverable
- **Reactivation**: `POST /api/profile/me/reactivate`
- **Permanent deletion**: `DELETE /api/profile/me` — requires password and explicit confirmation

### Lockout & Brute-Force Protection
- Account lock after N failed attempts (default 5)
- Automatic unlock after timeout (default 15 minutes)
- Counter reset on successful login
- Separate lockout for API keys (5 attempts, 15 minutes)
- Separate lockout for MFA backup codes (3 attempts, 30 seconds)

---

## 2. Multi-Factor Authentication (MFA)

### TOTP (Time-based One-Time Password)
- Standard RFC 6238 algorithm with Google Authenticator / compatible apps
- Enrollment: `POST /api/mfa/enroll` → returns secret, QR code (base64), 10 backup codes
- QR code generated server-side with `qrcode` library
- Enrollment verification: `POST /api/mfa/verify` with first TOTP code
- TOTP secret encrypted at rest (AES-GCM) with key derived from `SECRET_KEY`

### Backup Codes
- 10 one-time codes generated at enrollment
- Usable instead of TOTP (8+ characters)
- Regeneratable: `POST /api/mfa/regenerate-backup-codes`
- Dedicated lockout: 3 failed attempts → 30-second wait
- Codes are hash-verified (bcrypt), never in plaintext after generation

### Trusted Devices
- "Remember this device" option during MFA login
- Fingerprinting: user-agent + IP
- Trusted device list: `GET /api/mfa/trusted-devices`
- Removal: `DELETE /api/mfa/trusted-devices/{id}`
- Trusted device → skip MFA on subsequent logins

### MFA in OAuth2 Flow
- During `POST /oauth2/authorize`: if MFA active → redirect to MFA page
- `POST /oauth2/mfa-verify` — verify code, complete auth code
- Trust device option available in OAuth2 flow as well

### MFA in API Token Flow
- `POST /api/token` returns `mfa_required: true` + session token
- `POST /api/mfa/verify-login` — verify and return JWT access token

### MFA Administration
- Admin can reset a user's MFA: `POST /api/admin/users/{id}/reset-mfa`
- Admin dashboard shows percentage of users with MFA enabled
- User filter by `mfa_enabled` in admin search

---

## 3. Passkeys (WebAuthn / FIDO2)

### Registration
- `POST /api/passkey/register/begin` — generates credential creation options
- Relying Party ID and Origin configurable via env
- Dynamic RP ID/Origin detection from headers (supports reverse proxy/playground)
- Excludes already-registered passkeys to prevent duplicates
- `POST /api/passkey/register/complete` — verifies attestation, saves credential
- Challenge with 5-minute expiration

### Passwordless Authentication
- `POST /api/passkey/auth/begin` — receives email, returns assertion options
- Rate limit: 10 attempts/minute
- `POST /api/passkey/auth/complete` — verifies assertion, returns JWT access token
- Supports platform authenticator (Touch ID, Windows Hello) and cross-platform (YubiKey)

### Passkey Metadata
- Tracking: `device_type`, `transports`, `backup_eligible`, `backup_state`
- `last_used_at` updated on every authentication
- Sign count to detect authenticator cloning

### User Management
- `GET /api/passkey/list` — lists user's passkeys
- `DELETE /api/passkey/{credential_id}` — removes a passkey
- Dedicated HTML page: `/passkeys`

### Admin Management
- `GET /api/admin/users/{id}/passkeys` — passkey count
- `GET /api/admin/users/{id}/passkeys/list` — full list
- `DELETE /api/admin/users/{id}/passkeys/{credential_id}` — forced removal

---

## 4. OAuth 2.0 Authorization Server

### Authorization Code Flow (with PKCE)
- `GET /oauth2/authorize` — displays login form with OAuth2 parameters
- `POST /oauth2/authorize` — authenticates user, creates authorization code (or forwards to MFA/consent)
- Verifies `client_id`, `redirect_uri` (against client whitelist)
- Scope validation against client configuration
- PKCE mandatory for public clients (S256)
- PKCE configurable per client (optional for confidential)
- One-time authorization code with expiration (default 10 minutes)
- Race-condition protection: lock + optimistic concurrency versioning on code redemption

### Token Endpoint
- `POST /oauth2/token` — supports 3 grant types:

#### Authorization Code → Token
- Requires `code`, `redirect_uri`, client authentication
- Supports `client_secret_basic` (HTTP Basic Auth) and `client_secret_post`
- Public vs confidential clients: secret required only for confidential
- PKCE validation: `code_verifier` → SHA256 → compared with `code_challenge`
- Issues: access token (JWT RS256), refresh token, ID token (if scope `openid`)
- Refresh token with automatic rotation

#### Client Credentials
- `grant_type=client_credentials` with `client_id` + `client_secret`
- Token tied to client, no real user
- Perfect for M2M / service-to-service

#### Refresh Token
- `grant_type=refresh_token` with rotation
- Old refresh token invalidated, new one issued
- Cascade revocation if an already-used refresh token is reused (theft detection)
- IP address tracked for audit

### Token Revocation (RFC 7009)
- `POST /oauth2/revoke` — revokes refresh token
- For JWT access tokens: stateless, not revocable but logged
- Always returns 200 OK (anti-scanning)

### Token Introspection (RFC 7662)
- `POST /oauth2/introspect` — resource server queries token metadata
- Requires client authentication
- Supports access token and refresh token
- Standard RFC 7662 response with `active`, `scope`, `sub`, `exp`, `iat`, etc.

### Logout (RP-Initiated)
- `GET /oauth2/logout` — supports `id_token_hint`, `post_logout_redirect_uri`, `state`
- Redirect URI validation (client whitelist, allows localhost in dev)
- `POST /oauth2/logout` — logout with Bearer token, audit logging
- Stateless: client must delete tokens on its side

### Callback Endpoint
- `GET /callback` — HTML test page showing received authorization code

---

## 5. OpenID Connect (OIDC)

### Discovery
- `GET /.well-known/openid-configuration` — complete OIDC metadata
- `GET /.well-known/jwks.json` — public keys in JWK format (RFC 7517)
- Includes only `active` and `verifying` keys (excludes `revoked`)

### ID Token
- Issued with `authorization_code` grant when scope `openid` is requested
- Contains user claims based on scopes: `profile`, `email`, `phone`, `address`
- RS256-signed with active keyring key
- Supports `nonce` to prevent replay
- Includes `auth_time` claim

### UserInfo Endpoint
- `GET /oauth2/userinfo` — returns user claims via Bearer token
- Requires `openid` scope in token
- Supported scopes: `openid`, `profile`, `email`, `phone`, `address`

### Supported Standards
- Scopes: `openid`, `profile`, `email`, `phone`, `address`, `offline_access`
- Response types: `code`, `token`, `id_token` and hybrid combinations
- Grant types: `authorization_code`, `implicit`, `refresh_token`, `client_credentials`
- PKCE: `S256` (mandatory for public clients)

---

## 6. OAuth2 / OIDC Authentication Flows

This section describes the complete OAuth2/OIDC authentication flows handled by AuthGlow,
from the protocol perspective (request/response sequence).

### Authorization Code Flow (with PKCE) — for Web Apps and SPAs

The main flow for web and single-page applications, the only one involving
direct user interaction with AuthGlow (login, MFA, consent).

```
  User            Client App          AuthGlow             Resource Server
    |                  |                   |                       |
    |  (1) click login |                   |                       |
    |<-----------------|                   |                       |
    |                  | (2) GET /oauth2/authorize                |
    |                  |  ?response_type=code                     |
    |                  |  &client_id=...                          |
    |                  |  &redirect_uri=...                       |
    |                  |  &scope=openid profile email             |
    |                  |  &state=random                           |
    |                  |  &code_challenge=SHA256(verifier)        |
    |                  |  &code_challenge_method=S256             |
    |                  |------------------>|                       |
    |                  |                   |                       |
    |                  | (3) Login form + CSRF token              |
    |                  |<------------------|                       |
    |                  |                   |                       |
    |  (4) enter email |                   |                       |
    |     + password   |                   |                       |
    |<-----------------|                   |                       |
    |                  | (5) POST /oauth2/authorize               |
    |                  |  email, password, csrf_token, ...        |
    |                  |------------------>|                       |
    |                  |                   | (6) Validation:       |
    |                  |                   |  - credentials        |
    |                  |                   |  - client_id          |
    |                  |                   |  - redirect_uri       |
    |                  |                   |  - authorized scopes  |
    |                  |                   |  - account lockout?   |
    |                  |                   |                       |
    |                  |                   | (7) If MFA active and |
    |                  |                   |  device NOT trusted   |
    |                  |                   |  → MFA page           |
    |                  | (7a) MFA form     |                       |
    |                  |<------------------|                       |
    |                  | (7b) POST /oauth2/mfa-verify              |
    |                  |  code, session_token, csrf_token         |
    |                  |------------------>|                       |
    |                  |                   |                       |
    |                  | (8) If MFA OK (or skip), redirect to      |
    |                  |  /oauth2/consent?session_token=...       |
    |                  |<------------------| (303 redirect)        |
    |                  |                   |                       |
    |                  | (9) GET /oauth2/consent?session_token=... |
    |                  |------------------>|                       |
    |                  |                   | (10) If consent       |
    |                  |                   |  already given +      |
    |                  |                   |  remember: skip →     |
    |                  |                   |  direct redirect      |
    |                  |                   |  with code            |
    |                  |                   |                       |
    |  (11) review     | (12) Consent screen                      |
    |   scopes         |<------------------|                       |
    |<-----------------|                   |                       |
    |                  | (13) POST /oauth2/consent                |
    |                  |  approved=true, remember=true            |
    |                  |  session_token, csrf_token               |
    |                  |------------------>|                       |
    |                  |                   |                       |
    |                  | (14) Redirect with authorization code     |
    |                  |  ?code=AUTH_CODE&state=...               |
    |                  |<------------------| (303 redirect)        |
    |                  |                   |                       |
    |                  | (15) POST /oauth2/token                  |
    |                  |  grant_type=authorization_code           |
    |                  |  code=AUTH_CODE                          |
    |                  |  redirect_uri=...                        |
    |                  |  code_verifier=PLAINTEXT (for PKCE)      |
    |                  |  + client auth (Basic or form)           |
    |                  |------------------>|                       |
    |                  |                   | (16) Validation:      |
    |                  |                   |  - code exists        |
    |                  |                   |  - client_id match    |
    |                  |                   |  - redirect_uri match |
    |                  |                   |  - PKCE S256 verifier |
    |                  |                   |  - code not used      |
    |                  |                   |                       |
    |                  | (17) Token response                      |
    |                  |  { access_token, refresh_token,          |
    |                  |    token_type, expires_in,               |
    |                  |    id_token (if scope=openid) }          |
    |                  |<------------------|                       |
    |                  |                   |                       |
    |                  | (18) GET /api/resource                   |
    |                  |  Authorization: Bearer <access_token>    |
    |                  |------------------------------------------>|
    |                  |                   |                       |
    |                  | (19) Resource data                        |
    |                  |<------------------------------------------|
```

**Flow specifics:**
- **CSRF**: each form (login, MFA, consent) includes a `csrf_token` tied to an HttpOnly `session_id` cookie
- **PKCE**: S256 mandatory for public clients (`is_confidential=false`); for confidential clients the code_challenge can be omitted if `require_pkce=false`
- **MFA**: if the user has MFA active and the device is not trusted, the flow pauses after login and shows the MFA page; after MFA verification, consent proceeds
- **Consent skip**: if the user has already consented with the "remember" option, the consent screen step is skipped and the authorization code is obtained directly
- **One-time code**: authorization code is single-use (protected by lock + cross-process CAS)
- **Refresh token rotation**: each refresh token use invalidates the previous one and issues a new one; if an already-used token is presented again, ALL of the user's refresh tokens are revoked (theft detection)
- **ID token**: issued only if `openid` is among the requested scopes; RS256-signed, contains `nonce` and `auth_time`

### Client Credentials Flow — Machine-to-Machine

Service-to-service authentication flow without user interaction.

```
  Client App (M2M)          AuthGlow               Resource API
        |                      |                        |
        | (1) POST /oauth2/token                       |
        |  grant_type=client_credentials               |
        |  client_id=...                               |
        |  client_secret=...                           |
        |  scope=read write                            |
        |--------------------->|                        |
        |                      | (2) Validation:        |
        |                      |  - client_id & secret  |
        |                      |  - client active?      |
        |                      |  - authorized scopes   |
        |                      |                        |
        | (3) Token response   |                        |
        |  { access_token,     |                        |
        |    token_type,       |                        |
        |    expires_in }      |                        |
        |<---------------------|                        |
        |                      |                        |
        | (4) GET /api/secure                           |
        |  Authorization: Bearer <access_token>         |
        |---------------------------------------------->|
        |                      |                        |
        | (5) Resource data    |                        |
        |<----------------------------------------------|
```

**Specifics:**
- No refresh token issued (ephemeral)
- Token tied to `client_id` (not a real user)
- Scopes limited to those granted to the client
- Perfect for automation, CI/CD, cron jobs, microservices

### Refresh Token Flow — Rotation and Theft Detection

Flow for obtaining new access tokens without requiring login.

```
  Client App                 AuthGlow
      |                         |
      | (1) POST /oauth2/token |
      |  grant_type=refresh_token
      |  refresh_token=RT_OLD
      |  client_id=...
      |------------------------>|
      |                         | (2) Validation:
      |                         |  - RT exists?
      |                         |  - RT expired?
      |                         |  - RT already used? → THEFT! Revoke all user tokens
      |                         |  - RT revoked?
      |                         |  - client_id match?
      |                         |
      | (3a) Success:          |
      |  { access_token,       |
      |    refresh_token=RT_NEW,  ← new RT, old one invalidated
      |    token_type,         |
      |    expires_in }        |
      |<------------------------|
      |                         |
      | (3b) Theft detected:    |
      |  401 "Token reuse      |
      |  detected. All tokens   |
      |  revoked for security." |
      |<------------------------|
```

**Specifics:**
- Each use invalidates the previous refresh token
- New refresh token has same expiration as the original (not extended)
- If an already-used token is presented again → automatic revocation of all user's refresh tokens
- Refresh tokens are stored as SHA256 hashes on the filesystem

### OpenID Connect Discovery Flow

Auto-configuration flow for OIDC clients.

```
  Client OIDC              AuthGlow
      |                        |
      | (1) GET /.well-known/openid-configuration
      |   (OIDC metadata)      |
      |----------------------->|
      | (2) JSON with all      |
      |   endpoints and        |
      |   supported capabilities|
      |<-----------------------|
      |                        |
      | (3) GET /.well-known/jwks.json
      |   (public keys)        |
      |----------------------->|
      | (4) JSON JWK set with  |
      |   active and verifying |
      |   RSA keys             |
      |<-----------------------|
      |                        |
      | (5) GET /oauth2/userinfo
      |  Authorization: Bearer <access_token>
      |----------------------->|
      | (6) User claims        |
      |  (sub, email, name,    |
      |   picture, etc.)       |
      |<-----------------------|
```

### OpenID Connect Logout (RP-Initiated)

```
  User          Client App          AuthGlow
    |                |                   |
    | (1) click      |                   |
    |  "logout"      |                   |
    |<---------------|                   |
    |                | (2) GET /oauth2/logout
    |                |  ?id_token_hint=ID_TOKEN
    |                |  &post_logout_redirect_uri=...
    |                |  &state=...
    |                |------------------>|
    |                |                   | (3) Validate ID token
    |                |                   |  Verify redirect URI
    |                |                   |  Audit log
    |                |                   |
    |                | (4) Redirect to   |
    |                |  post_logout_redirect_uri
    |                |<------------------|
    |                |                   |
    | (5) landing page                   |
    |<---------------|                   |
```

**Note:** AuthGlow is stateless — logout only invalidates the refresh token server-side.
The client is responsible for deleting access tokens and ID tokens on its side.

### Token Revocation (RFC 7009)

```
  Client App              AuthGlow
      |                       |
      | POST /oauth2/revoke  |
      |  token=REFRESH_TOKEN |
      |  token_type_hint=refresh_token
      |  (optional: client auth)
      |---------------------->|
      |                       | Marks RT as revoked
      |                       | Audit log
      |                       |
      | 200 OK (always)       |  ← Per RFC 7009, always 200
      |<----------------------|    to prevent scanning
```

### Token Introspection (RFC 7662)

```
  Resource Server            AuthGlow
      |                         |
      | POST /oauth2/introspect |
      |  token=ACCESS_OR_RT     |
      |  (client auth required) |
      |------------------------>|
      |                         | For JWT access token:
      |                         |  decode, verify expiration
      |                         | For refresh token:
      |                         |  verify DB, revocation status
      |                         |
      | { active: true/false,   |
      |   scope, sub, exp,      |
      |   client_id, username } |
      |<------------------------|
```

### OAuth2/OIDC Endpoint Overview

| Endpoint | Method | RFC | Description |
|----------|--------|-----|-------------|
| `/oauth2/authorize` | GET, POST | 6749 | Authorization endpoint (login + consent) |
| `/oauth2/token` | POST | 6749 | Token endpoint (code→token, client_credentials, refresh) |
| `/oauth2/revoke` | POST | 7009 | Token revocation |
| `/oauth2/introspect` | POST | 7662 | Token introspection |
| `/oauth2/userinfo` | GET | OIDC | UserInfo endpoint |
| `/oauth2/logout` | GET, POST | OIDC | RP-Initiated logout |
| `/oauth2/consent` | GET, POST | — | Consent screen |
| `/oauth2/mfa-verify` | POST | — | MFA verification during OAuth2 flow |
| `/.well-known/openid-configuration` | GET | OIDC | Discovery metadata |
| `/.well-known/jwks.json` | GET | 7517 | JWK Set |
| `/oauth2/register` | POST | 7591 | Dynamic Client Registration |

---

## 7. OAuth2 Client Management

### Client CRUD (Admin)
- `POST /api/oauth-clients` — create OAuth2 client (10/hour rate limit)
- `GET /api/oauth-clients` — list with pagination and `active_only` filter
- `GET /api/oauth-clients/{id}` — single client detail
- `PUT /api/oauth-clients/{id}` — update (30/hour)
- `DELETE /api/oauth-clients/{id}` — delete (20/hour)
- Client secret is shown ONLY ONCE at creation

### Client Properties
- `client_name`, `description`, `logo_uri`, `homepage_uri`, `terms_uri`, `privacy_uri`
- `redirect_uris` — whitelist URI list for callback
- `allowed_scopes` — authorized scopes for this client
- `grant_types` — allowed grant types (authorization_code, client_credentials, etc.)
- `is_confidential` — if true, requires client_secret for token endpoint
- `require_pkce` — if true, PKCE mandatory
- `require_consent` — if true, always show consent screen
- `access_token_lifetime` / `refresh_token_lifetime` — per-client custom TTL
- Activation/deactivation: `POST /api/oauth-clients/{id}/activate` and `/deactivate`

### Secret Rotation
- `POST /api/oauth-clients/{id}/rotate-secret` (10/day)
- New secret shown only once

### Default Client (Fallback)
- Predefined client via env (`OAUTH2_CLIENT_ID`/`OAUTH2_CLIENT_SECRET`)
- Acts as fallback if no dynamic client matches

---

## 8. OAuth2 Consent Management

### Consent Screen
- `GET /oauth2/consent?session_token=...` — displays consent UI
- Shows: client name, logo, description, requested scopes with descriptions
- If user already consented → auto skip, direct redirect with auth code
- `POST /oauth2/consent` — approve/deny
- "remember" option — saves consent permanently
- Denial → redirect with `error=access_denied`

### Consent Administration
- `GET /api/admin/oauth-consents` — list all consents with pagination
- Filter by user email
- Includes: user, client, scope, dates, revocation status
- `POST /api/admin/oauth-consents/{id}/revoke` — revoke consent

### Scope Descriptions
- `read`, `write`, `admin`, `email`, `profile`, `openid` with human-readable descriptions
- Configurable for consent UI

---

## 9. Refresh Token Management

### Creation and Rotation
- Refresh tokens created during `authorization_code` grant
- Automatic rotation: each use invalidates the previous one and generates a new one
- Theft detection: if an already-used token is presented again → revocation of ALL tokens for that user
- Configurable expiration (default 7 days for users, customizable per client)
- IP address and user-agent recorded

### Cache
- In-memory cache of valid refresh tokens (TTL 60s, max 5000 entries)
- Reduces I/O on storage for frequent validations

### Administration
- `GET /api/admin/sessions` — list active sessions with details (user, client, IP, scopes)
- `POST /api/admin/tokens/refresh/{id}/revoke` — admin forced revocation
- `POST /api/admin/sessions/cleanup` — cleanup expired tokens
- `POST /api/tokens/refresh/revoke-all` — user revokes all their tokens (logout everywhere)

---

## 10. API Key Management

### Creation and Usage
- `POST /api/keys` — create API key (10/hour) with name, scopes, optional expiration
- Key (plaintext) shown ONLY ONCE
- Format: `ak_` + random (stored as bcrypt hash)
- Usable via `X-API-Key` header or `Authorization: Bearer ak_...`
- `POST /api/token/api-key` — exchange API key for JWT access token

### CRUD
- `GET /api/keys` — list own keys
- `GET /api/keys/{id}` — single key detail (owner or admin)
- `PATCH /api/keys/{id}` — update (name, scopes, status)
- `POST /api/keys/{id}/revoke` — revoke (deactivates but retains)
- `DELETE /api/keys/{id}` — permanent deletion

### Security
- Brute-force lockout: after 5 failed attempts → 15-minute lock
- Audit trail: creation, usage, revocation, lockout
- Usage tracking: IP, user-agent, last use timestamp
- Keys are bcrypt-hashed — never in plaintext after creation

### Administration
- `GET /api/admin/keys` — global list with pagination and filtering
- `GET /api/admin/users/{id}/keys` — keys for a specific user
- `POST /api/admin/keys/cleanup` — cleanup expired/inactive keys

---

## 11. Role-Based Access Control (RBAC)

### Permission Management
- Full CRUD: `POST/GET/DELETE /api/rbac/permissions`
- Each permission has `name` and `description`
- Examples: `users.read`, `users.write`, `roles.read`, `roles.write`
- Protected by `require_admin()` or `require_permission("roles.read")`

### Role Management
- Full CRUD: `POST/GET/PATCH/DELETE /api/rbac/roles`
- Each role has: `name`, `description`, `permissions` (list), `is_system`
- System roles are not editable/deletable
- `PATCH` supports partial update
- `GET /api/rbac/roles/{id}` returns full details with permission expand

### User-Role Assignment
- `POST /api/rbac/user-roles` — assign role to user
- Supports assignment expiration (`expires_at`)
- `DELETE /api/rbac/user-roles/{user_id}/{role_id}` — remove role
- `GET /api/rbac/user-roles/{user_id}` — roles for a user (with role name and email)
- Users can see their own roles; viewing others' roles requires `roles.read`

### User Permissions
- `GET /api/rbac/users/{user_id}/permissions` — all effective permissions
- Calculated as union of permissions across all assigned roles
- Includes `is_admin` flag
- Cache and recursive resolution

---

## 12. Admin Dashboard & Management

### Dashboard Statistics
- `GET /api/admin/stats` — aggregate statistics:
  - Total, active, inactive users
  - Users with MFA and percentage
  - New users: today, this week, this month
- `GET /api/admin/stats/timeseries` — time-series chart data (30 days default)

### User Management
- Search with filters: free text (email, first name, last name), `is_active`, `mfa_enabled`
- Server-side pagination: `limit` (max 500) and `offset`
- `GET /api/admin/users/search` — search and filter
- `GET /api/admin/users/{id}` — user detail (AdminUserDetail)
- `PUT /api/admin/users/{id}` — modify (active, email verified, scopes, name)
- `DELETE /api/admin/users/{id}` — delete (cannot delete self)
- Prevents self-deactivation/deletion

### Bulk Operations
- `POST /api/admin/users/bulk` — bulk operations:
  - `activate` / `deactivate`
  - `assign_scope` / `remove_scope`
  - `delete`
- Success/failure report per user

### Session Management
- `GET /api/admin/sessions` — all active sessions with details
- `POST /api/admin/tokens/refresh/{id}/revoke`
- `POST /api/admin/sessions/cleanup`
- HTML page: `/admin/sessions`

### Consent Management
- `GET /api/admin/oauth-consents` — consent list with email filter
- `POST /api/admin/oauth-consents/{id}/revoke`
- HTML page: `/admin/oauth-consents`

### Password Reset Admin
- `GET /api/admin/password-resets` — reset token list (with `active_only` filter)
- `GET /api/admin/users/{id}/password-resets` — token for a specific user
- `POST /api/admin/users/{id}/revoke-resets` — revoke all active tokens
- `POST /api/admin/password-resets/cleanup` — cleanup expired
- `GET /api/admin/password-resets/stats` — statistics

### Admin HTML Pages
- `/admin` — dashboard
- `/admin/users` — user management
- `/admin/oauth-clients` — OAuth2 clients
- `/admin/api-keys` — API keys
- `/admin/password-resets` — password resets
- `/admin/sessions` — active sessions
- `/admin/oauth-consents` — consents
- `/admin/rbac` — roles and permissions
- `/admin/jwk-keys` — JWK keys
- `/admin/playground` — API playground

### JWK Key Management
- `GET /api/admin/jwk-keys` — keyring status (all keys)
- `POST /api/admin/jwk-keys/rotate` — rotate active key
- `POST /api/admin/jwk-keys/{kid}/revoke` — revoke key (not the active one)
- Active key is copied as symlink to `private_key.pem` / `public_key.pem`

---

## 13. User Profile & Preferences

### User Profile
- `GET /api/profile/me` — full profile (UserProfileResponse)
- `PATCH /api/profile/me` — update profile (name, avatar, bio, etc.)
- `GET /api/users/me` — basic authenticated user info

### Password Change
- `POST /api/profile/me/change-password` — requires current + new password

### Email Change
- `POST /api/profile/me/change-email` — requires password for confirmation, sends verification

### User Preferences
- `GET /api/profile/me/preferences` — saved preferences
- `PATCH /api/profile/me/preferences` — update preferences
- Model: `UserPreferences` (theme, language, notifications, etc.)

### User HTML Pages
- `/dashboard` — personal dashboard
- `/profile` — profile management
- `/passkeys` — passkey management

---

## 14. Security Features

### Rate Limiting
- Per-IP with `slowapi` (in-memory, suitable for single-process)
- Protected endpoints: login (5/min), registration (5/min), password reset (5/hour), MFA verify (3/min), API key creation (10/hour), client creation (10/hour), etc.
- `SlowAPIMiddleware` integrated

### CSRF Protection
- CSRF tokens generated per form (login, MFA, consent)
- Server-side validation with session ID via HttpOnly cookie
- Token expiration: 30 minutes

### CORS
- Configurable via env: `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, etc.
- Automatic warning if `credentials=true` with wildcard headers (violation of Fetch standard)
- Support for multiple origins, specific methods and headers

### Security Headers (OWASP)
- Content-Security-Policy (configurable)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- X-Permitted-Cross-Domain-Policies: none
- HSTS (HTTP Strict Transport Security) with max-age and includeSubdomains
- Permissions-Policy (configurable)

### HTTPS Enforcement
- HTTP → HTTPS redirect middleware in production
- Configurable status code (default 301)
- Disableable via `ENFORCE_HTTPS=false` for local development

### Request Body Size Limiter
- Middleware rejecting payloads over `MAX_REQUEST_BODY_SIZE_MB` (default 10MB)
- Protects against DoS via oversized payloads

### Timing Side-Channel Protection
- Random jitter (0-50ms) in responses for users not found
- I/O padding to normalize "found" vs "not found" profiles
- Disableable via `TIMING_LEAK_PROTECTION=false`

### Password Policy
- Configurable minimum length (default 8)
- Configurable requirements: uppercase, lowercase, digits, special characters
- Server-side validation on registration, change, reset

### Password Hashing
- bcrypt for all passwords (users, API key hash, backup codes)
- TOTP secret encrypted with AES-GCM (key derived from SECRET_KEY)
- RSA private keys encrypted at rest

### Secure Token Design
- JWT signed with RS256 (RSA 2048 bit)
- ID token, access token, refresh token with separate scopes and TTLs
- Refresh token: SHA256 hash in database, never in plaintext
- Automatic key rotation with configurable period (default 90 days)

---

## 15. Storage System (fsspec)

### Supported Backends
- **file** — local filesystem, human-readable JSON
- **s3** — AWS S3
- **gcs** — Google Cloud Storage
- **abfs** — Azure Blob Storage

### Configuration
- `STORAGE_BACKEND` and `STORAGE_PATH` via env
- Cloud-specific credentials: `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.
- Transparent switch: no code changes needed

### Stored Data
- Users (JSON per user_id)
- Email index (email → user_id mapping)
- OAuth2 authorization codes
- Refresh tokens
- OAuth2 clients
- OAuth2 consents
- API keys
- Email verification tokens
- Password reset tokens
- MFA backup codes
- MFA trusted devices
- Passkeys
- RBAC roles and permissions
- User-role assignments
- User preferences

### Concurrency
- Named in-process locks for read-modify-write operations
- Optimistic concurrency versioning for cross-process (authorization code redemption)
- Separate locks per resource (`user:<id>`, `email_index`, etc.)

### Cache
- In-memory user cache (TTL 300s, max 2000 entries)
- Refresh token cache (TTL 60s, max 5000 entries)
- Cachetools (TTLCache)

---

## 16. Email System

### Supported Providers
- **console** — prints to stdout (development)
- **file_storage** — saves JSON to filesystem (debug)
- **smtp** — sends via SMTP server
- **sendgrid** — SendGrid API
- **mailgun** — Mailgun API

### Email Templates
- HTML + text for each type:
  - **email_verification** — email verification link
  - **welcome** — welcome with temporary password (invite) or without (registration)
  - **password_reset** — reset link with expiration
  - **security_alert** — security event notification
- Customizable Jinja2 templates
- Variables: `user_name`, `verification_url`, `reset_url`, `company_name`, etc.

### Configuration
- `EMAIL_BACKEND`, `EMAIL_FROM_ADDRESS`, `EMAIL_FROM_NAME`
- SMTP: host, port, username, password, TLS
- SendGrid: API key
- Mailgun: API key, domain

---

## 17. UI Customization & Theming

### Environment Variables
- `UI_COMPANY_NAME`, `UI_SUPPORT_EMAIL`
- `UI_PRIVACY_POLICY_URL`, `UI_TERMS_OF_SERVICE_URL`
- `UI_LOGO_URL`, `UI_LOGO_DARK_URL` (light/dark mode)
- `UI_PRIMARY_COLOR`, `UI_SECONDARY_COLOR`
- `UI_BACKGROUND_COLOR`, `UI_BACKGROUND_DARK`
- `UI_TEXT_COLOR`, `UI_TEXT_DARK`

### Theme
- Light/dark mode support
- CSS custom properties (variables) injected from `ui_context`
- Client-side theme switcher JS
- Applied uniformly to all pages (login, dashboard, admin, consent, etc.)

### UI Context
- `ui_context` dictionary computed once (cached property on Settings)
- Injected into all Jinja2 templates

---

## 18. Initial Setup Wizard

### Flow
- `GET /api/setup/check` — verifies if setup is needed (no users in the system)
- `GET /setup` — HTML wizard page (redirects to `/login` if already completed)
- `POST /api/setup/create-admin` — create first admin
  - Validates password policy
  - Sets scopes: `["read", "write", "admin"]`
  - Auto-verifies email (skips verification for initial admin)
  - Blocked if users already exist

---

## 19. Audit Logging

### Tracked Events
- **Authentication**: `login_success`, `login_failed`, `login_mfa_required`, `login_success_with_mfa`, `login_attempt_while_locked`
- **Account**: `user_registered`, `user_invited`, `user_updated`, `user_deleted`, `account_locked`
- **MFA**: `mfa_enabled`, `mfa_verification_failed`
- **OAuth2**: `oauth_client_created/updated/deleted/activated/deactivated`, `oauth_client_secret_rotated`, `oauth2_consent_granted/denied`, `oauth_consent_revoked_by_admin`
- **Token**: `refresh_token_revoked`, `refresh_token_revoked_by_admin`, `access_token_revoke_requested`, `oidc_logout`, `oidc_logout_post`
- **API Keys**: `api_key_created/updated/revoked/deleted`, `api_key_used`, `api_key_auth_success`, `api_key_invalid`, `api_key_locked`
- **Password**: `password_reset_requested/completed/failed`, `password_changed`, `password_change_failed`
- **Email**: `email_verified`, `email_verification_failed`, `email_verification_resent`
- **Admin**: `bulk_user_operation`, `mfa_reset_by_admin`, `admin_deleted_passkey`, `admin_revoked_password_resets`, `jwk_key_rotated/revoked`
- **System**: `all_refresh_tokens_revoked`

### Severity Levels
- `info`, `warning`, `high`

### Email Privacy
- `AUDIT_EMAIL_LOG_LEVEL`: `mask` (default, obscures domain), `hash` (SHA256), `none` (plaintext)

---

## 20. JWK Key Management

### Keyring
- Multi-key system with keyring (`data/keys/keyring.json`)
- Each key has: `kid` (unique ID), `created_at`, `status`, `algorithm`, `key_size`
- States: `active` (only one), `verifying` (to validate existing tokens after rotation), `revoked`
- Smart loading: migrates legacy format, generates new keys if absent, auto-rotates

### Auto-Rotation
- Configurable period: `JWT_KEY_ROTATION_DAYS` (default 90)
- Disableable: `JWT_AUTO_ROTATE=false`
- On rotation: new key `active`, old key → `verifying`
- JWKS endpoint exposes both `active` and `verifying` (not `revoked`)

### Manual Rotation
- `POST /api/admin/jwk-keys/rotate` — immediate
- `POST /api/admin/jwk-keys/{kid}/revoke` — revoke (not the active one)

### Backward Compatibility
- Symlinks `private_key.pem` and `public_key.pem` → active key
- Legacy format supported and automatically migrated

### Encryption
- Private keys encrypted with AES-GCM (key derived from `SECRET_KEY`)
- Public keys in plaintext (needed for JWT/JWKS verification)

---

## 21. Middleware & Infrastructure

### Middleware Stack
1. `SlowAPIMiddleware` — rate limiting
2. `CORSMiddleware` — cross-origin
3. `SecurityHeadersMiddleware` — OWASP headers
4. `MaxBodySizeMiddleware` — request size limit
5. `HttpsEnforcementMiddleware` — HTTP→HTTPS redirect

### Framework
- **FastAPI** with `uvicorn`
- OpenAPI docs (`/docs`, `/redoc`) disableable via env `ENABLE_DOCS=false`
- Health check: `GET /health`

### Configuration
- `pydantic-settings` with `.env` file
- Automatic validation (`SECRET_KEY` min 32 characters, warning for placeholder)
- `get_settings()` with `@lru_cache` (singleton)

### Docker
- Dockerfile included (Python 3.13-slim)
- Volume for data persistence (`/app/data`)
- `.env` file for runtime configuration

### Test Suite
- Unit tests (35 files): every service and model
- Integration tests (8 files): API endpoints, CORS, HTTPS, rate limit, security headers
- `conftest.py` with shared fixtures
- `pytest` with `asyncio_mode=auto`

---

## Application Module Overview

| Module | API Router | Service | Models |
|--------|-----------|---------|--------|
| Auth | `api/auth.py` | `services/jwt.py`, `services/password.py`, `services/oauth2.py` | `models/user.py`, `models/token.py` |
| MFA | `api/mfa.py` | `services/mfa.py` | `models/mfa.py` |
| Passkeys | `api/passkey.py` | `services/passkey.py` | `models/passkey.py` |
| OAuth2 Adv. | `api/oauth2_advanced.py` | `services/refresh_token.py` | `models/refresh_token.py` |
| OAuth2 Clients | `api/oauth_client.py` | `services/oauth_client.py` | `models/oauth_client.py` |
| OAuth2 Consent | `api/oauth_consent_handler.py` | `services/oauth_consent.py`, `services/session.py` | `models/oauth_consent.py`, `models/session.py` |
| OIDC | `api/oidc.py` | `services/oidc.py`, `services/jwt.py` | `models/oidc.py` |
| RBAC | `api/rbac.py` | `services/rbac.py` | `models/rbac.py` |
| API Keys | `api/api_key.py` | `services/api_key.py` | `models/api_key.py` |
| Password Reset | `api/password_reset.py` | `services/password_reset.py` | `models/password_reset.py` |
| Email Verify | `api/email_verification.py` | `services/email_verification.py` | `models/email_verification.py` |
| User Profile | `api/user_profile.py` | `services/user_profile.py` | `models/user_profile.py` |
| Admin | `api/admin.py` | (uses storage, audit, mfa, passkey services) | `models/admin.py` |
| Setup | `api/setup.py` | — | — |
| Core | — | `services/storage.py`, `services/audit.py`, `services/csrf.py`, `services/email/`, `services/security_notifications.py` | — |
| Config | — | `core/config.py`, `core/crypto.py`, `core/cache.py`, `core/rate_limit.py`, `core/concurrency.py`, `core/password.py`, `core/permissions.py`, `core/datetime.py`, `core/async_io.py` | — |
| Middleware | — | `middleware/security_headers.py`, `middleware/request_body_size.py`, `middleware/https_enforcement.py` | — |
| Email | — | `services/email/base.py`, `console.py`, `factory.py`, `file_storage.py` | `models/email.py` |
