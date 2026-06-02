# AuthGlow - Feature Catalog

> Catalogo completo delle funzionalità. Questo file serve come riferimento unico per rigenerare documentazione, frontend (React), e consent screen.  
> Per i dettagli implementativi, consultare il codice sorgente (`authglow/api/`, `authglow/services/`, `authglow/models/`).

---

## 1. User Authentication & Lifecycle

### Registrazione Pubblica
- Endpoint `POST /api/users` — self-registration con validazione password
- Disabilitabile via env `ALLOW_PUBLIC_REGISTRATION=false`
- Password policy configurabile: lunghezza minima, richiesta uppercase/lowercase/digits/caratteri speciali
- Alla registrazione: invio email di verifica + email di benvenuto
- Audit log: evento `user_registered`

### Login
- **Login tradizionale**: `POST /api/token` (OAuth2PasswordRequestForm) con username/password
- **Login OAuth2**: `GET/POST /oauth2/authorize` → login form → redirect con authorization code
- Rate limiting: 5 tentativi/minuto su `/api/token`, 10/minuto su `/oauth2/authorize`
- Account lockout automatico dopo 5 tentativi falliti consecutivi (15 minuti, configurabile)
- Protezione user enumeration: messaggi di errore identici per email inesistente e password errata
- Timing side-channel protection: jitter casuale nelle risposte per utenti non trovati

### Invito Utenti (Admin)
- `POST /api/users/invite` — admin invita un nuovo utente
- Generazione password temporanea, email di benvenuto con link verifica
- Audit log: evento `user_invited`

### Password Reset
- `POST /api/password/reset/request` — richiede reset (5/ora, anti-abuso)
- Risposta sempre "success" per prevenire enumerazione email
- Token one-time con scadenza 30 minuti
- `POST /api/password/reset/confirm` — imposta nuova password con validazione
- Revoca automatica dei token attivi pre-esistenti dell'utente

### Cambio Password (utente autenticato)
- `POST /api/password/change` — richiede password corrente
- Impedisce riutilizzo della stessa password
- `POST /api/profile/me/change-password` — endpoint alternativo via profilo

### Verifica Email
- Email di verifica inviata alla registrazione
- `GET /verify-email?token=...` — pagina HTML di conferma
- `POST /api/email/verify` — verifica via API
- `POST /api/email/resend-verification` — ri-invio email (5/ora)
- `GET /resend-verification` — pagina HTML per richiedere ri-invio

### Account Lifecycle
- **Disattivazione**: `POST /api/profile/me/deactivate` — account disattivato ma recuperabile
- **Riattivazione**: `POST /api/profile/me/reactivate`
- **Cancellazione permanente**: `DELETE /api/profile/me` — richiede password e conferma esplicita

### Lockout & Protezione Brute-Force
- Blocco account dopo N tentativi falliti (default 5)
- Sblocco automatico dopo timeout (default 15 minuti)
- Reset contatore al login riuscito
- Lockout separato per API keys (5 tentativi, 15 minuti)
- Lockout separato per backup codes MFA (3 tentativi, 30 secondi)

---

## 2. Multi-Factor Authentication (MFA)

### TOTP (Time-based One-Time Password)
- Algoritmo standard RFC 6238 con Google Authenticator / app compatibili
- Enrollment: `POST /api/mfa/enroll` → restituisce secret, QR code (base64), 10 backup codes
- QR code generato lato server con `qrcode` library
- Verifica enrollment: `POST /api/mfa/verify` con primo codice TOTP
- Secret TOTP cifrato a riposo (AES-GCM) con chiave derivata da `SECRET_KEY`

### Backup Codes
- 10 codici monouso generati all'enrollment
- Utilizzabili al posto del TOTP (8+ caratteri)
- Rigenerabili: `POST /api/mfa/regenerate-backup-codes`
- Lockout dedicato: 3 tentativi errati → 30 secondi di attesa
- I codici sono hash-verificati (bcrypt), mai in chiaro dopo la generazione

### Trusted Devices
- Opzione "Ricorda questo dispositivo" durante login MFA
- Fingerprinting: user-agent + IP
- Lista dispositivi trusted: `GET /api/mfa/trusted-devices`
- Rimozione: `DELETE /api/mfa/trusted-devices/{id}`
- Se dispositivo trusted → skip MFA nei login successivi

### MFA nel Flusso OAuth2
- Durante `POST /oauth2/authorize`: se MFA attivo → redirect a pagina MFA
- `POST /oauth2/mfa-verify` — verifica codice, completa l'auth code
- Trust device option disponibile anche nel flusso OAuth2

### MFA nel Flusso API Token
- `POST /api/token` restituisce `mfa_required: true` + session token
- `POST /api/mfa/verify-login` — verifica e restituisce JWT access token

### Amministrazione MFA
- Admin può resettare MFA di un utente: `POST /api/admin/users/{id}/reset-mfa`
- Dashboard admin mostra percentuale utenti con MFA attivo
- Filtro utenti per `mfa_enabled` nella ricerca admin

---

## 3. Passkeys (WebAuthn / FIDO2)

### Registrazione
- `POST /api/passkey/register/begin` — genera credential creation options
- Relying Party ID e Origin configurabili via env
- Rilevamento dinamico di RP ID/Origin da header (supporta reverse proxy/playground)
- Esclude passkey già registrate per evitare duplicati
- `POST /api/passkey/register/complete` — verifica attestation, salva credenziale
- Challenge con scadenza 5 minuti

### Autenticazione Passwordless
- `POST /api/passkey/auth/begin` — riceve email, restituisce assertion options
- Rate limit: 10 tentativi/minuto
- `POST /api/passkey/auth/complete` — verifica assertion, restituisce JWT access token
- Supporta platform authenticator (Touch ID, Windows Hello) e cross-platform (YubiKey)

### Metadata Passkey
- Tracciamento: `device_type`, `transports`, `backup_eligible`, `backup_state`
- `last_used_at` aggiornato ad ogni autenticazione
- Sign count per rilevare clonazione autenticatore

### Gestione Utente
- `GET /api/passkey/list` — elenca passkey dell'utente
- `DELETE /api/passkey/{credential_id}` — rimuove una passkey
- Pagina HTML dedicata: `/passkeys`

### Gestione Admin
- `GET /api/admin/users/{id}/passkeys` — conteggio passkey
- `GET /api/admin/users/{id}/passkeys/list` — lista completa
- `DELETE /api/admin/users/{id}/passkeys/{credential_id}` — rimozione forzata

---

## 4. OAuth 2.0 Authorization Server

### Authorization Code Flow (con PKCE)
- `GET /oauth2/authorize` — mostra login form con parametri OAuth2
- `POST /oauth2/authorize` — autentica utente, crea authorization code (o inoltra a MFA/consent)
- Verifica `client_id`, `redirect_uri` (contro whitelist del client)
- Validazione scope contro configurazione del client
- PKCE obbligatorio per client pubblici (S256)
- PKCE configurabile per client (opzionale per confidential)
- Authorization code monouso con scadenza (default 10 minuti)
- Protezione race-condition: lock + optimistic concurrency versioning sul code redemption

### Token Endpoint
- `POST /oauth2/token` — supporta 3 grant type:

#### Authorization Code → Token
- Richiede `code`, `redirect_uri`, client authentication
- Supporta `client_secret_basic` (HTTP Basic Auth) e `client_secret_post`
- Client pubblici vs confidential: secret richiesto solo per confidential
- Validazione PKCE: `code_verifier` → SHA256 → confronto con `code_challenge`
- Emette: access token (JWT RS256), refresh token, ID token (se scope `openid`)
- Refresh token con rotazione automatica

#### Client Credentials
- `grant_type=client_credentials` con `client_id` + `client_secret`
- Token legato al client, senza utente reale
- Perfetto per M2M / service-to-service

#### Refresh Token
- `grant_type=refresh_token` con rotazione
- Il vecchio refresh token viene invalidato, ne viene emesso uno nuovo
- Rivocazione in cascata se un refresh token già usato viene riutilizzato (rilevamento theft)
- Ip address tracciato per audit

### Token Revocation (RFC 7009)
- `POST /oauth2/revoke` — revoca refresh token
- Per access token JWT: essendo stateless, non revocabili ma loggati
- Restituisce sempre 200 OK (anti-scanning)

### Token Introspection (RFC 7662)
- `POST /oauth2/introspect` — resource server interroga metadata token
- Richiede client authentication
- Supporta access token e refresh token
- Risposta standard RFC 7662 con `active`, `scope`, `sub`, `exp`, `iat`, etc.

### Logout (RP-Initiated)
- `GET /oauth2/logout` — supporta `id_token_hint`, `post_logout_redirect_uri`, `state`
- Validazione redirect URI (whitelist del client, permite localhost in dev)
- `POST /oauth2/logout` — logout con Bearer token, audit logging
- Stateless: il client deve eliminare i token lato suo

### Callback Endpoint
- `GET /callback` — pagina HTML di test che mostra authorization code ricevuto

---

## 5. OpenID Connect (OIDC)

### Discovery
- `GET /.well-known/openid-configuration` — metadati completi OIDC
- `GET /.well-known/jwks.json` — chiavi pubbliche in formato JWK (RFC 7517)
- Include solo chiavi `active` e `verifying` (esclude `revoked`)

### ID Token
- Emesso con `authorization_code` grant quando scope `openid` è richiesto
- Contiene claims utente basati sugli scope: `profile`, `email`, `phone`, `address`
- Firmato RS256 con chiave attiva del keyring
- Supporta `nonce` per prevenire replay
- Include `auth_time` claim

### UserInfo Endpoint
- `GET /oauth2/userinfo` — restituisce claims utente via Bearer token
- Richiede scope `openid` nel token
- Scope supportati: `openid`, `profile`, `email`, `phone`, `address`

### Supported Standards
- Scopes: `openid`, `profile`, `email`, `phone`, `address`, `offline_access`
- Response types: `code`, `token`, `id_token` e combinazioni ibride
- Grant types: `authorization_code`, `implicit`, `refresh_token`, `client_credentials`
- PKCE: `S256` (obbligatorio per client pubblici)

---

## 6. OAuth2 / OIDC Authentication Flows

Questa sezione descrive i flussi di autenticazione OAuth2/OIDC completi gestiti da AuthGlow,
dal punto di vista del protocollo (sequenza di richieste e risposte).

### Authorization Code Flow (con PKCE) — per Web App e SPA

Il flusso principale per applicazioni web e single-page, l'unico che coinvolge
l'interazione diretta dell'utente con AuthGlow (login, MFA, consent).

```
  Utente           Client App          AuthGlow             Resource Server
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
    |                  |                   | (6) Validazione:      |
    |                  |                   |  - credenziali        |
    |                  |                   |  - client_id          |
    |                  |                   |  - redirect_uri       |
    |                  |                   |  - scope autorizzati  |
    |                  |                   |  - account lockout?   |
    |                  |                   |                       |
    |                  |                   | (7) Se MFA attivo e   |
    |                  |                   |  dispositivo NON      |
    |                  |                   |  trusted → MFA page   |
    |                  | (7a) MFA form     |                       |
    |                  |<------------------|                       |
    |                  | (7b) POST /oauth2/mfa-verify              |
    |                  |  code, session_token, csrf_token         |
    |                  |------------------>|                       |
    |                  |                   |                       |
    |                  | (8) Se MFA OK (o skip), redirect a        |
    |                  |  /oauth2/consent?session_token=...       |
    |                  |<------------------| (303 redirect)        |
    |                  |                   |                       |
    |                  | (9) GET /oauth2/consent?session_token=... |
    |                  |------------------>|                       |
    |                  |                   | (10) Se consenso già  |
    |                  |                   |  prestato + remember: |
    |                  |                   |  skip → redirect      |
    |                  |                   |  diretto con code     |
    |                  |                   |                       |
    |  (11) review     | (12) Consent screen                      |
    |   scopes         |<------------------|                       |
    |<-----------------|                   |                       |
    |                  | (13) POST /oauth2/consent                |
    |                  |  approved=true, remember=true            |
    |                  |  session_token, csrf_token               |
    |                  |------------------>|                       |
    |                  |                   |                       |
    |                  | (14) Redirect con authorization code      |
    |                  |  ?code=AUTH_CODE&state=...               |
    |                  |<------------------| (303 redirect)        |
    |                  |                   |                       |
    |                  | (15) POST /oauth2/token                  |
    |                  |  grant_type=authorization_code           |
    |                  |  code=AUTH_CODE                          |
    |                  |  redirect_uri=...                        |
    |                  |  code_verifier=PLAINTEXT (per PKCE)      |
    |                  |  + client auth (Basic o form)            |
    |                  |------------------>|                       |
    |                  |                   | (16) Validazione:     |
    |                  |                   |  - code esistente     |
    |                  |                   |  - client_id match    |
    |                  |                   |  - redirect_uri match |
    |                  |                   |  - PKCE S256 verifier |
    |                  |                   |  - code non usato     |
    |                  |                   |                       |
    |                  | (17) Token response                      |
    |                  |  { access_token, refresh_token,          |
    |                  |    token_type, expires_in,               |
    |                  |    id_token (se scope=openid) }          |
    |                  |<------------------|                       |
    |                  |                   |                       |
    |                  | (18) GET /api/resource                   |
    |                  |  Authorization: Bearer <access_token>    |
    |                  |------------------------------------------>|
    |                  |                   |                       |
    |                  | (19) Resource data                        |
    |                  |<------------------------------------------|
```

**Particolarità del flusso:**
- **CSRF**: ogni form (login, MFA, consent) include un `csrf_token` legato a un `session_id` cookie HttpOnly
- **PKCE**: S256 obbligatorio per client pubblici (`is_confidential=false`); per client confidential il code_challenge può essere omesso se `require_pkce=false`
- **MFA**: se l'utente ha MFA attivo e il dispositivo non è trusted, il flusso si interrompe dopo il login e mostra la pagina MFA; dopo verifica MFA, si procede con il consent
- **Consent skip**: se l'utente ha già prestato consenso con l'opzione "remember", il passaggio del consent screen viene saltato e si ottiene direttamente l'authorization code
- **One-time code**: l'authorization code è monouso (protetto da lock + CAS cross-process)
- **Refresh token rotation**: ogni utilizzo del refresh token invalida il precedente e ne emette uno nuovo; se un token già usato viene ri-presentato, TUTTI i refresh token dell'utente vengono revocati (theft detection)
- **ID token**: emesso solo se tra gli scope richiesti c'è `openid`; firmato RS256, contiene `nonce` e `auth_time`

### Client Credentials Flow — Machine-to-Machine

Flusso per autenticazione service-to-service senza interazione utente.

```
  Client App (M2M)          AuthGlow               Resource API
        |                      |                        |
        | (1) POST /oauth2/token                       |
        |  grant_type=client_credentials               |
        |  client_id=...                               |
        |  client_secret=...                           |
        |  scope=read write                            |
        |--------------------->|                        |
        |                      | (2) Validazione:       |
        |                      |  - client_id e secret  |
        |                      |  - client attivo?      |
        |                      |  - scope autorizzati   |
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

**Particolarità:**
- Non viene emesso refresh token (effimero)
- Il token è legato al `client_id` (non a un utente reale)
- Scope limitati a quelli concessi al client
- Perfetto per automation, CI/CD, cron job, microservizi

### Refresh Token Flow — Rotazione e Rilevamento Furto

Flusso per ottenere nuovi access token senza richiedere login.

```
  Client App                 AuthGlow
      |                         |
      | (1) POST /oauth2/token |
      |  grant_type=refresh_token
      |  refresh_token=RT_OLD
      |  client_id=...
      |------------------------>|
      |                         | (2) Validazione:
      |                         |  - RT esiste?
      |                         |  - RT scaduto?
      |                         |  - RT già usato? → THEFT! Revoca tutti i token utente
      |                         |  - RT revocato?
      |                         |  - client_id match?
      |                         |
      | (3a) Successo:         |
      |  { access_token,       |
      |    refresh_token=RT_NEW,  ← nuovo RT, il vecchio è invalidato
      |    token_type,         |
      |    expires_in }        |
      |<------------------------|
      |                         |
      | (3b) Furto rilevato:    |
      |  401 "Token reuse      |
      |  detected. All tokens   |
      |  revoked for security." |
      |<------------------------|
```

**Particolarità:**
- Ogni utilizzo invalida il refresh token precedente
- Il nuovo refresh token ha la stessa scadenza dell'originale (non estesa)
- Se un token già usato viene ripresentato → revoca automatica di tutti i refresh token dell'utente
- I refresh token sono memorizzati come hash SHA256 sul filesystem

### OpenID Connect Discovery Flow

Flusso di auto-configurazione per client OIDC.

```
  Client OIDC              AuthGlow
      |                        |
      | (1) GET /.well-known/openid-configuration
      |   (metadata OIDC)      |
      |----------------------->|
      | (2) JSON con tutti     |
      |   gli endpoint e le    |
      |   capability supportate|
      |<-----------------------|
      |                        |
      | (3) GET /.well-known/jwks.json
      |   (chiavi pubbliche)   |
      |----------------------->|
      | (4) JSON JWK set con   |
      |   chiavi RSA attive    |
      |   e in verifying       |
      |<-----------------------|
      |                        |
      | (5) GET /oauth2/userinfo
      |  Authorization: Bearer <access_token>
      |----------------------->|
      | (6) Claims utente      |
      |  (sub, email, name,    |
      |   picture, etc.)       |
      |<-----------------------|
```

### OpenID Connect Logout (RP-Initiated)

```
  Utente         Client App          AuthGlow
    |                |                   |
    | (1) click      |                   |
    |  "logout"      |                   |
    |<---------------|                   |
    |                | (2) GET /oauth2/logout
    |                |  ?id_token_hint=ID_TOKEN
    |                |  &post_logout_redirect_uri=...
    |                |  &state=...
    |                |------------------>|
    |                |                   | (3) Valida ID token
    |                |                   |  Verifica redirect URI
    |                |                   |  Audit log
    |                |                   |
    |                | (4) Redirect a    |
    |                |  post_logout_redirect_uri
    |                |<------------------|
    |                |                   |
    | (5) landing page                   |
    |<---------------|                   |
```

**Nota:** AuthGlow è stateless — la logout invalida solo il refresh token lato server.
Il client è responsabile di eliminare access token e ID token lato suo.

### Token Revocation (RFC 7009)

```
  Client App              AuthGlow
      |                       |
      | POST /oauth2/revoke  |
      |  token=REFRESH_TOKEN |
      |  token_type_hint=refresh_token
      |  (opzionale: client auth)
      |---------------------->|
      |                       | Marca RT come revocato
      |                       | Audit log
      |                       |
      | 200 OK (sempre)       |  ← Per RFC 7009, sempre 200
      |<----------------------|    per prevenire scanning
```

### Token Introspection (RFC 7662)

```
  Resource Server            AuthGlow
      |                         |
      | POST /oauth2/introspect |
      |  token=ACCESS_OR_RT     |
      |  (client auth richiesta)|
      |------------------------>|
      |                         | Per access token JWT:
      |                         |  decodifica, verifica scadenza
      |                         | Per refresh token:
      |                         |  verifica DB, stato revoca
      |                         |
      | { active: true/false,   |
      |   scope, sub, exp,      |
      |   client_id, username } |
      |<------------------------|
```

### Riepilogo Endpoint OAuth2/OIDC

| Endpoint | Metodo | RFC | Descrizione |
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
| `/oauth2/register` | — | 7591 | (Dichiarato in discovery, non implementato) |

---

## 7. OAuth2 Client Management

### CRUD Client (Admin)
- `POST /api/oauth-clients` — crea client OAuth2 (10/ora rate limit)
- `GET /api/oauth-clients` — lista con paginazione e filtro `active_only`
- `GET /api/oauth-clients/{id}` — dettaglio singolo client
- `PUT /api/oauth-clients/{id}` — aggiorna (30/ora)
- `DELETE /api/oauth-clients/{id}` — elimina (20/ora)
- Il client secret viene mostrato UNA SOLA volta alla creazione

### Proprietà del Client
- `client_name`, `description`, `logo_uri`, `homepage_uri`, `terms_uri`, `privacy_uri`
- `redirect_uris` — lista URI whitelist per il callback
- `allowed_scopes` — scope autorizzati per questo client
- `grant_types` — grant type permessi (authorization_code, client_credentials, etc.)
- `is_confidential` — se true, richiede client_secret per token endpoint
- `require_pkce` — se true, PKCE obbligatorio
- `require_consent` — se true, mostra sempre consent screen
- `access_token_lifetime` / `refresh_token_lifetime` — TTL personalizzati per client
- Attivazione/disattivazione: `POST /api/oauth-clients/{id}/activate` e `/deactivate`

### Rotazione Secret
- `POST /api/oauth-clients/{id}/rotate-secret` (10/giorno)
- Nuovo secret mostrato una sola volta

### Client di Default (Fallback)
- Client predefinito via env (`OAUTH2_CLIENT_ID`/`OAUTH2_CLIENT_SECRET`)
- Funge da fallback se nessun client dinamico corrisponde

---

## 8. OAuth2 Consent Management

### Consent Screen
- `GET /oauth2/consent?session_token=...` — mostra UI di consenso
- Visualizza: nome client, logo, descrizione, scope richiesti con descrizioni
- Se utente ha già consentito → skip automatico, redirect diretto con auth code
- `POST /oauth2/consent` — approva/nega
- Opzione "remember" — salva il consenso permanentemente
- Denial → redirect con `error=access_denied`

### Amministrazione Consensi
- `GET /api/admin/oauth-consents` — lista tutti i consensi con paginazione
- Filtro per email utente
- Include: utente, client, scope, date, stato revoca
- `POST /api/admin/oauth-consents/{id}/revoke` — revoca consenso

### Scope Descriptions
- `read`, `write`, `admin`, `email`, `profile`, `openid` con descrizioni human-readable
- Configurabili per la UI di consenso

---

## 9. Refresh Token Management

### Creazione e Rotazione
- Refresh token creati durante `authorization_code` grant
- Rotazione automatica: ogni utilizzo invalida il precedente e ne genera uno nuovo
- Rilevamento theft: se un token già usato viene ripresentato → revoca di TUTTI i token di quell'utente
- Scadenza configurabile (default 7 giorni per utenti, personalizzabile per client)
- IP address e user-agent registrati

### Cache
- Cache in-memory dei refresh token validi (TTL 60s, max 5000 entries)
- Riduce I/O su storage per validazioni frequenti

### Amministrazione
- `GET /api/admin/sessions` — lista sessioni attive con dettagli (utente, client, IP, scopes)
- `POST /api/admin/tokens/refresh/{id}/revoke` — revoca forzata admin
- `POST /api/admin/sessions/cleanup` — pulizia token scaduti
- `POST /api/tokens/refresh/revoke-all` — utente revoca tutti i propri token (logout everywhere)

---

## 10. API Key Management

### Creazione e Utilizzo
- `POST /api/keys` — crea API key (10/ora) con nome, scopes, scadenza opzionale
- La key (plaintext) viene mostrata UNA SOLA volta
- Formato: `ak_` + random (memorizzato come hash bcrypt)
- Utilizzabile via header `X-API-Key` o `Authorization: Bearer ak_...`
- `POST /api/token/api-key` — scambia API key per JWT access token

### CRUD
- `GET /api/keys` — elenca le proprie key
- `GET /api/keys/{id}` — dettaglio singola key (proprietario o admin)
- `PATCH /api/keys/{id}` — aggiorna (nome, scopes, stato)
- `POST /api/keys/{id}/revoke` — revoca (disattiva ma mantiene)
- `DELETE /api/keys/{id}` — eliminazione permanente

### Sicurezza
- Brute-force lockout: dopo 5 tentativi falliti → blocco 15 minuti
- Audit trail: creazione, utilizzo, revoca, lockout
- Tracciamento utilizzo: IP, user-agent, timestamp ultimo uso
- Le key vengono hashate (bcrypt) — mai in chiaro dopo la creazione

### Amministrazione
- `GET /api/admin/keys` — lista globale con paginazione e filtro
- `GET /api/admin/users/{id}/keys` — key di un utente specifico
- `POST /api/admin/keys/cleanup` — pulizia key scadute/inattive

---

## 11. Role-Based Access Control (RBAC)

### Permission Management
- CRUD completo: `POST/GET/DELETE /api/rbac/permissions`
- Ogni permission ha `name` e `description`
- Esempi: `users.read`, `users.write`, `roles.read`, `roles.write`
- Protetto da `require_admin()` o `require_permission("roles.read")`

### Role Management
- CRUD completo: `POST/GET/PATCH/DELETE /api/rbac/roles`
- Ogni ruolo ha: `name`, `description`, `permissions` (lista), `is_system`
- Ruoli di sistema non modificabili/eliminabili
- `PATCH` supporta aggiornamento parziale
- `GET /api/rbac/roles/{id}` restituisce dettagli completi con permission expand

### User-Role Assignment
- `POST /api/rbac/user-roles` — assegna ruolo a utente
- Supporta scadenza dell'assegnazione (`expires_at`)
- `DELETE /api/rbac/user-roles/{user_id}/{role_id}` — rimuove ruolo
- `GET /api/rbac/user-roles/{user_id}` — ruoli di un utente (con nome ruolo e email)
- Gli utenti possono vedere i propri ruoli; per vedere quelli altrui serve `roles.read`

### User Permissions
- `GET /api/rbac/users/{user_id}/permissions` — tutte le permission effettive
- Calcolate come unione delle permission di tutti i ruoli assegnati
- Include flag `is_admin`
- Cache e risoluzione ricorsiva

---

## 12. Admin Dashboard & Management

### Dashboard Statistics
- `GET /api/admin/stats` — statistiche aggregate:
  - Utenti totali, attivi, inattivi
  - Utenti con MFA e percentuale
  - Nuovi utenti: oggi, questa settimana, questo mese
- `GET /api/admin/stats/timeseries` — dati per grafici temporali (30 giorni default)

### User Management
- Ricerca con filtri: testo libero (email, nome, cognome), `is_active`, `mfa_enabled`
- Paginazione server-side: `limit` (max 500) e `offset`
- `GET /api/admin/users/search` — ricerca e filtro
- `GET /api/admin/users/{id}` — dettaglio utente (AdminUserDetail)
- `PUT /api/admin/users/{id}` — modifica (attivo, email verificata, scopes, nome)
- `DELETE /api/admin/users/{id}` — elimina (non può eliminare se stesso)
- Impedisce la propria disattivazione/eliminazione

### Bulk Operations
- `POST /api/admin/users/bulk` — operazioni in massa:
  - `activate` / `deactivate`
  - `assign_scope` / `remove_scope`
  - `delete`
- Report successi/fallimenti per ogni utente

### Session Management
- `GET /api/admin/sessions` — tutte le sessioni attive con dettagli
- `POST /api/admin/tokens/refresh/{id}/revoke`
- `POST /api/admin/sessions/cleanup`
- Pagina HTML: `/admin/sessions`

### Consent Management
- `GET /api/admin/oauth-consents` — lista consensi con filtro email
- `POST /api/admin/oauth-consents/{id}/revoke`
- Pagina HTML: `/admin/oauth-consents`

### Password Reset Admin
- `GET /api/admin/password-resets` — lista token di reset (con filtro active_only)
- `GET /api/admin/users/{id}/password-resets` — token di un utente specifico
- `POST /api/admin/users/{id}/revoke-resets` — revoca tutti i token attivi
- `POST /api/admin/password-resets/cleanup` — pulizia scaduti
- `GET /api/admin/password-resets/stats` — statistiche

### Pagine HTML Admin
- `/admin` — dashboard
- `/admin/users` — gestione utenti
- `/admin/oauth-clients` — client OAuth2
- `/admin/api-keys` — API keys
- `/admin/password-resets` — reset password
- `/admin/sessions` — sessioni attive
- `/admin/oauth-consents` — consensi
- `/admin/rbac` — ruoli e permessi
- `/admin/jwk-keys` — chiavi JWK
- `/admin/playground` — API playground

### JWK Key Management
- `GET /api/admin/jwk-keys` — stato del keyring (tutte le chiavi)
- `POST /api/admin/jwk-keys/rotate` — ruota chiave attiva
- `POST /api/admin/jwk-keys/{kid}/revoke` — revoca chiave (non attiva)
- La chiave attiva viene copiata come symlink a `private_key.pem` / `public_key.pem`

---

## 13. User Profile & Preferences

### Profilo Utente
- `GET /api/profile/me` — profilo completo (UserProfileResponse)
- `PATCH /api/profile/me` — aggiorna profilo (nome, avatar, bio, etc.)
- `GET /api/users/me` — info base utente autenticato

### Cambio Password
- `POST /api/profile/me/change-password` — richiede password corrente + nuova

### Cambio Email
- `POST /api/profile/me/change-email` — richiede password per conferma, invia verifica

### Preferenze Utente
- `GET /api/profile/me/preferences` — preferenze salvate
- `PATCH /api/profile/me/preferences` — aggiorna preferenze
- Modello: `UserPreferences` (theme, lingua, notifiche, etc.)

### Pagine HTML Utente
- `/dashboard` — dashboard personale
- `/profile` — gestione profilo
- `/passkeys` — gestione passkey

---

## 14. Security Features

### Rate Limiting
- Per-IP con `slowapi` (in-memory, adatto a single-process)
- Endpoint protetti: login (5/min), registrazione (5/min), password reset (5/ora), MFA verify (3/min), creazione API key (10/ora), creazione client (10/ora), etc.
- Middleware `SlowAPIMiddleware` integrato

### CSRF Protection
- Token CSRF generati per ogni form (login, MFA, consent)
- Validazione lato server con session ID via cookie `HttpOnly`
- Scadenza token: 30 minuti

### CORS
- Configurabile via env: `CORS_ALLOWED_ORIGINS`, `CORS_ALLOW_CREDENTIALS`, etc.
- Warning automatico se `credentials=true` con headers wildcard (violazione Fetch standard)
- Supporto origini multiple, metodi e headers specifici

### Security Headers (OWASP)
- Content-Security-Policy (configurabile)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- X-Permitted-Cross-Domain-Policies: none
- HSTS (HTTP Strict Transport Security) con max-age e includeSubdomains
- Permissions-Policy (configurabile)

### HTTPS Enforcement
- Middleware di redirect HTTP → HTTPS in produzione
- Status code configurabile (default 301)
- Disabilitabile via `ENFORCE_HTTPS=false` per sviluppo locale

### Request Body Size Limiter
- Middleware che rifiuta payload oltre `MAX_REQUEST_BODY_SIZE_MB` (default 10MB)
- Protegge da DoS via payload oversize

### Timing Side-Channel Protection
- Jitter casuale (0-50ms) nelle risposte per utenti non trovati
- Padding I/O per uniformare il profilo "found" vs "not found"
- Disabilitabile via `TIMING_LEAK_PROTECTION=false`

### Password Policy
- Lunghezza minima configurabile (default 8)
- Requisiti configurabili: uppercase, lowercase, digits, special characters
- Validazione lato server in registrazione, cambio, reset

### Password Hashing
- bcrypt per tutte le password (utenti, API key hash, backup codes)
- Secret TOTP cifrato con AES-GCM (chiave derivata da SECRET_KEY)
- Chiavi private RSA cifrate a riposo

### Secure Token Design
- JWT firmati con RS256 (RSA 2048 bit)
- ID token, access token, refresh token con scopi e TTL separati
- Refresh token: hash SHA256 nel database, mai in chiaro
- Key rotation automatica con periodo configurabile (default 90 giorni)

---

## 15. Storage System (fsspec)

### Backend Supportati
- **file** — filesystem locale, JSON human-readable
- **s3** — AWS S3
- **gcs** — Google Cloud Storage
- **abfs** — Azure Blob Storage

### Configurazione
- `STORAGE_BACKEND` e `STORAGE_PATH` via env
- Credenziali cloud specifiche: `AWS_ACCESS_KEY_ID`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.
- Switch trasparente: nessun cambio di codice

### Dati Memorizzati
- Utenti (JSON per user_id)
- Email index (email → user_id mapping)
- Codici di autorizzazione OAuth2
- Refresh token
- OAuth2 client
- OAuth2 consensi
- API keys
- Token verifica email
- Token reset password
- Backup codes MFA
- Trusted devices MFA
- Passkey
- Ruoli e permessi RBAC
- Assegnazioni utente-ruolo
- Preferenze utente

### Concorrenza
- Named lock in-process per operazioni read-modify-write
- Optimistic concurrency versioning per cross-process (authorization code redemption)
- Lock separati per risorsa (`user:<id>`, `email_index`, etc.)

### Cache
- Cache utenti in-memory (TTL 300s, max 2000 entries)
- Cache refresh token (TTL 60s, max 5000 entries)
- Cachetools (TTLCache)

---

## 16. Email System

### Provider Supportati
- **console** — stampa su stdout (sviluppo)
- **file_storage** — salva JSON su filesystem (debug)
- **smtp** — invio via server SMTP
- **sendgrid** — API SendGrid
- **mailgun** — API Mailgun

### Template Email
- HTML + testo per ogni tipo:
  - **email_verification** — link verifica email
  - **welcome** — benvenuto con password temporanea (invito) o senza (registrazione)
  - **password_reset** — link reset con scadenza
  - **security_alert** — notifica eventi di sicurezza
- Template Jinja2 personalizzabili
- Variabili: `user_name`, `verification_url`, `reset_url`, `company_name`, etc.

### Configurazione
- `EMAIL_BACKEND`, `EMAIL_FROM_ADDRESS`, `EMAIL_FROM_NAME`
- SMTP: host, port, username, password, TLS
- SendGrid: API key
- Mailgun: API key, domain

---

## 17. UI Customization & Theming

### Variabili d'Ambiente
- `UI_COMPANY_NAME`, `UI_SUPPORT_EMAIL`
- `UI_PRIVACY_POLICY_URL`, `UI_TERMS_OF_SERVICE_URL`
- `UI_LOGO_URL`, `UI_LOGO_DARK_URL` (light/dark mode)
- `UI_PRIMARY_COLOR`, `UI_SECONDARY_COLOR`
- `UI_BACKGROUND_COLOR`, `UI_BACKGROUND_DARK`
- `UI_TEXT_COLOR`, `UI_TEXT_DARK`

### Tema
- Supporto light/dark mode
- CSS custom properties (variabili) iniettate da `ui_context`
- Theme switcher JS lato client
- Applicato uniformemente a tutte le pagine (login, dashboard, admin, consent, etc.)

### Contesto UI
- Dizionario `ui_context` calcolato una volta (cached property su Settings)
- Iniettato in tutti i template Jinja2

---

## 18. Initial Setup Wizard

### Flusso
- `GET /api/setup/check` — verifica se setup necessario (nessun utente nel sistema)
- `GET /setup` — pagina HTML wizard (reindirizza a `/login` se già completato)
- `POST /api/setup/create-admin` — crea primo admin
  - Valida password policy
  - Imposta scopes: `["read", "write", "admin"]`
  - Auto-verifica email (salta verifica per admin iniziale)
  - Bloccato se esistono già utenti

---

## 19. Audit Logging

### Eventi Tracciati
- **Autenticazione**: `login_success`, `login_failed`, `login_mfa_required`, `login_success_with_mfa`, `login_attempt_while_locked`
- **Account**: `user_registered`, `user_invited`, `user_updated`, `user_deleted`, `account_locked`
- **MFA**: `mfa_enabled`, `mfa_verification_failed`
- **OAuth2**: `oauth_client_created/updated/deleted/activated/deactivated`, `oauth_client_secret_rotated`, `oauth2_consent_granted/denied`, `oauth_consent_revoked_by_admin`
- **Token**: `refresh_token_revoked`, `refresh_token_revoked_by_admin`, `access_token_revoke_requested`, `oidc_logout`, `oidc_logout_post`
- **API Keys**: `api_key_created/updated/revoked/deleted`, `api_key_used`, `api_key_auth_success`, `api_key_invalid`, `api_key_locked`
- **Password**: `password_reset_requested/completed/failed`, `password_changed`, `password_change_failed`
- **Email**: `email_verified`, `email_verification_failed`, `email_verification_resent`
- **Admin**: `bulk_user_operation`, `mfa_reset_by_admin`, `admin_deleted_passkey`, `admin_revoked_password_resets`, `jwk_key_rotated/revoked`
- **Sistema**: `all_refresh_tokens_revoked`

### Livelli di Severità
- `info`, `warning`, `high`

### Privacy Email
- `AUDIT_EMAIL_LOG_LEVEL`: `mask` (default, oscura dominio), `hash` (SHA256), `none` (in chiaro)

---

## 20. JWK Key Management

### Keyring
- Sistema multi-chiave con keyring (`data/keys/keyring.json`)
- Ogni chiave ha: `kid` (ID univoco), `created_at`, `status`, `algorithm`, `key_size`
- Stati: `active` (una sola), `verifying` (per validate token esistenti dopo rotazione), `revoked`
- Caricamento intelligente: migra formato legacy, genera nuove chiavi se assente, auto-rota

### Auto-Rotazione
- Periodo configurabile: `JWT_KEY_ROTATION_DAYS` (default 90)
- Disabilitabile: `JWT_AUTO_ROTATE=false`
- Alla rotazione: nuova chiave `active`, vecchia chiave → `verifying`
- JWKS endpoint espone sia `active` che `verifying` (non `revoked`)

### Rotazione Manuale
- `POST /api/admin/jwk-keys/rotate` — immediata
- `POST /api/admin/jwk-keys/{kid}/revoke` — revoca (non la attiva)

### Backward Compatibility
- Symlink `private_key.pem` e `public_key.pem` → chiave attiva
- Formato legacy supportato e migrato automaticamente

### Crittografia
- Chiavi private cifrate con AES-GCM (chiave derivata da `SECRET_KEY`)
- Chiavi pubbliche in chiaro (necessarie per verifica JWT/JWKS)

---

## 21. Middleware & Infrastructure

### Stack Middleware
1. `SlowAPIMiddleware` — rate limiting
2. `CORSMiddleware` — cross-origin
3. `SecurityHeadersMiddleware` — OWASP headers
4. `MaxBodySizeMiddleware` — limite dimensione richieste
5. `HttpsEnforcementMiddleware` — redirect HTTP→HTTPS

### Framework
- **FastAPI** con `uvicorn`
- OpenAPI docs (`/docs`, `/redoc`) disabilitabili via env `ENABLE_DOCS=false`
- Health check: `GET /health`

### Configurazione
- `pydantic-settings` con `.env` file
- Validazione automatica (`SECRET_KEY` min 32 caratteri, warning per placeholder)
- `get_settings()` con `@lru_cache` (singleton)

### Docker
- Dockerfile incluso (Python 3.13-slim)
- Volume per persistenza dati (`/app/data`)
- `.env` file per configurazione runtime

### Test Suite
- Test unitari (35 file): ogni servizio e modello
- Test integrazione (8 file): API endpoints, CORS, HTTPS, rate limit, security headers
- `conftest.py` con fixtures condivise
- `pytest` con `asyncio_mode=auto`

---

## Riepilogo Moduli dell'Applicazione

| Modulo | API Router | Service | Models |
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
