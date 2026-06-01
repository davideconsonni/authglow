# AuthGlow Remediation Plan — Phase 2
# Sicurezza & Performance (Post-Phase1)

Questo documento estende il piano di remediation originale. I problemi CRITICAL/HIGH/MEDIUM di Phase 1
sono stati risolti (vedi `REMEDIATION.md`). Qui vengono tracciati i problemi di sicurezza e performance
ancora aperti.

Usa una sessione per fix, spunta ciò che completi.

---

## Legenda Stati

- `pending` — Da iniziare
- `in_progress` — In lavorazione
- `blocked` — Bloccato
- `done` — Completato e verificato
- `wontfix` — Deciso di non risolvere

---

## CRITICAL — Sicurezza

- [x] **S1 — `/oauth2/introspect` senza autenticazione**
  - File: `authglow/api/oauth2_advanced.py`
  - Problema: endpoint RFC 7662 accessibile senza credenziali. Chiunque può validare token.
  - Fix: richiedere `client_id` + `client_secret` (Basic Auth) o Bearer token per l'accesso.

- [x] **S2 — Nessuna protezione CSRF sui form POST**
  - File: `authglow/api/auth.py`, `authglow/api/oauth_consent_handler.py`, `authglow/api/mfa.py`, tutti i template HTML
  - Problema: login, consent, MFA verify sono POST senza token anti-CSRF. Un sito malevolo può forzare richieste.
  - Fix: generare `csrf_token` nella GET, inserirlo come hidden field nei form, validarlo nella POST corrispondente.
    Usare `secrets.token_urlsafe(32)` memorizzato in una sessione temporanea file-based con scadenza 30 minuti.
  - **Risolto**: Creato `authglow/services/csrf.py` (CSRFTokenService file-based con scadenza 30 minuti, `secrets.token_urlsafe(32)`).
    Cookie `csrf_session_id` HttpOnly/SameSite=Lax lega i token alla sessione browser.
    Protetti i 3 form POST principali: `/oauth2/authorize`, `/oauth2/mfa-verify`, `/oauth2/consent`.
    Test: 16 test in `tests/unit/test_csrf.py` (service, route validation, security properties).

- [x] **S3 — Secret key deboli / placeholder in `.env`**
  - File: `.env:13`, `authglow/core/config.py`
  - Problema: `SECRET_KEY` era `"your-secret-key-change-in-production-min-32-chars"`.
    Superava il controllo `min_length=32` ma non era una chiave crittografica.
    `JWT_SECRET_KEY` era presente nel file `.env` ma mai utilizzato dal codice Python
    (JWT usa chiavi RSA da file).
  - Fix: generata chiave reale con `openssl rand -hex 32`. Rimosso `JWT_SECRET_KEY` inutilizzato
    da `.env`. Aggiunto `warnings.warn()` all'avvio se `SECRET_KEY` contiene placeholder noti
    (`change-in-production`, `your-secret`, `your-jwt`, `your-`).
  - **Risolto**: `SECRET_KEY` sostituito con chiave crittografica generata. Validatore esteso
    con rilevazione placeholder + warning. `JWT_SECRET_KEY` rimosso da `.env`.
    Test: 10 test in `tests/unit/test_config.py` (rilevazione placeholder, case-insensitive,
    validazione lunghezza, chiavi reali, instantiation).

- [x] **S4 — CORS misconfiguration: credentials + wildcard headers**
  - File: `.env:90,96`, `authglow/core/config.py`
  - Problema: `CORS_ALLOW_CREDENTIALS=true` + `CORS_ALLOWED_HEADERS=*`. I browser rifiutano questa combinazione
    (viola lo standard fetch). Headers `*` viene ignorato quando `credentials=true`.
  - Fix: specificare header esplicitamente (`Authorization, Content-Type, X-Requested-With, Accept`) oppure
    impostare `CORS_ALLOW_CREDENTIALS=false` se non si usano cookie cross-origin. Aggiungere un warning
    di startup se la combinazione è rilevata.
  - **Risolto**: Default `cors_allowed_headers` cambiato da `"*"` a `"Authorization, Content-Type, X-Requested-With, Accept"`.
    Aggiunto check in `Settings.__init__()` che emette `UserWarning` se la combinazione pericolosa viene rilevata.
    `.env` aggiornato con header espliciti.
    Test: 3 test S4 in `tests/integration/test_cors.py` (warning triggered, no warning with explicit headers, no warning with credentials=false).

---

## HIGH — Sicurezza

- [x] **S5 — Chiave privata RSA in chiaro su disco**
  - File: `authglow/core/config.py`, `data/keys/private_key.pem`
  - Problema: `_generate_rsa_keys()` in `config.py` genera chiavi RSA 2048-bit e le salva senza cifratura
    in `data/keys/`. Se il filesystem viene compromesso, l'attaccante può firmare token arbitrari.
  - Fix opzioni:
    1. Cifrare la private key a riposo con AES-256-GCM usando `SECRET_KEY` (stesso schema di `crypto.py`).
    2. In cloud, usare KMS (AWS KMS, GCP KMS, Azure Key Vault).
    3. Caricare chiave da variabili d'ambiente invece che da file.
    4. Short-term: documentare che `data/keys/` deve avere permessi `0600`.
  - **Risolto**: Aggiunte `encrypt_private_key()` e `decrypt_private_key()` in `authglow/core/crypto.py`
    con schema AES-256-GCM + HKDF derivato da `SECRET_KEY` (prefisso `agk1:`).
    `get_or_generate_keys()` in `config.py` ora cifra la private key prima di salvarla su disco.
    `JWTService.__init__()` decifra la chiave al caricamento.
    Le chiavi pubbliche restano in chiaro (non sensibili).
    Test: 4 test S5 in `tests/unit/test_config.py` (cifratura su disco, roundtrip JWT, chiave pubblica in chiaro,
    verifica che i dati cifrati differiscano dal plaintext).

- [x] **S6 — Security headers assenti**
  - File: `authglow/main.py`
  - Problema: nessun middleware che aggiunge header di sicurezza.
  - Fix: aggiungere middleware (o usare libreria come `secure`) per:
    - `Content-Security-Policy`: `default-src 'self'`
    - `X-Frame-Options`: `DENY`
    - `X-Content-Type-Options`: `nosniff`
    - `Strict-Transport-Security`: `max-age=31536000; includeSubDomains` (solo in produzione)
    - `Referrer-Policy`: `strict-origin-when-cross-origin`
    - `X-XSS-Protection`: `0` (deprecato, CSP lo sostituisce)
  - **Risolto**: Creato `authglow/middleware/security_headers.py` (middleware ASGI puro, no `BaseHTTPMiddleware`).
    Headers configurati via `Settings` (`.env`): `CSP_HEADER`, `X_FRAME_OPTIONS`, `X_CONTENT_TYPE_OPTIONS`,
    `REFERRER_POLICY`, `X_PERMITTED_CROSS_DOMAIN_POLICIES`, `PERMISSIONS_POLICY`, `HSTS_MAX_AGE`,
    `HSTS_INCLUDE_SUBDOMAINS`. HSTS applicato solo quando `APP_ENV=production` (case-insensitive).
    Il middleware non sovrascrive header già impostati dall'applicazione.
    Test: 13 unit + 17 integration in `tests/unit/test_security_headers.py` e
    `tests/integration/test_security_headers.py` (presenza header, HSTS condizionale,
    customizzazione, override endpoint, websocket ignorato).

- [x] **S7 — Bug `change_password`: argomenti errati a `send_password_changed_alert`**
  - File: `authglow/services/user_profile.py`
  - Problema: chiama `self.security_service.send_password_changed_alert(user.email, user.first_name or "User", ip_address)`
    ma il metodo in `security_notifications.py` si aspetta `(user: User, ip_address: str)`.
    Causa errore runtime quando l'alert viene inviato.
  - Fix: passare `(user, ip_address)` invece di `(user.email, user.first_name or "User", ip_address)`.
  - **Risolto**: Corretto `user_profile.py:132-134` per passare l'oggetto `User` e `ip_address` direttamente.
    Test: 3 test S7 in `tests/unit/test_user_profile.py` (verifica tipo User in call args, ip_address esplicito, ip_address None di default).

- [x] **S8 — Nessun limite dimensione body richieste**
  - File: `authglow/main.py`
  - Problema: FastAPI/Starlette non impone limiti espliciti. Un attaccante può inviare payload enormi.
  - Fix: aggiungere `request.max_body_size` o middleware che limita `Content-Length` a ~10 MB.
    Opzioni: Starlette `MaximumContentLengthMiddleware` o `nginx` a monte.
  - **Risolto**: Creato `authglow/middleware/request_body_size.py` (MaxBodySizeMiddleware, ASGI puro).
    Controlla `Content-Length` header per rejection rapida, pre-legge il body per chunked encoding.
    Configurabile via `MAX_REQUEST_BODY_SIZE_MB` (default 10 MB). Middleware registrato in `main.py`
    dopo CORS e security headers.
    Test: 14 unit + 7 integration in `tests/unit/test_request_body_size.py` e
    `tests/integration/test_request_body_size.py` (Content-Length rejection, chunked encoding,
    edge cases, custom limit, response format).

---

## MEDIUM — Sicurezza

- [x] **S9 — Timing side-channel su lookup email**
  - File: `authglow/services/storage.py:get_user_by_email()`
  - Problema: il lookup via `email_index.json` non è constant-time. Un attaccante potrebbe dedurre
    l'esistenza di un'email misurando i tempi di risposta.
  - Fix: parzialmente mitigato dal rate limiting. Per una protezione completa, usare un tempo
    di risposta costante indipendentemente dal risultato (es. aggiungere un `await asyncio.sleep(random_ms)`
    o fare sempre hash lookup anche quando l'email non esiste).
  - **Risolto**: Aggiunto `timing_leak_protection: bool = True` in `Settings` (default abilitato).
    `get_user_by_email()` ora normalizza il profilo I/O quando l'email non esiste (simula un file read
    su path dummy `__timing_padding`) e aggiunge jitter casuale 0-49ms (`secrets.randbelow(50)`)
    dopo entrambi i percorsi. Quando `timing_leak_protection=false` nessun overhead.
    Test: 7 test in `tests/unit/test_storage.py` (found/not-found protetto, found/not-found
    non protetto, default abilitato, nessun side-effect su chiamate consecutive).

- [x] **S10 — Audit log contiene PII queryabile**
  - File: `authglow/services/audit.py`, `authglow/api/admin.py`
  - Problema: email in chiaro nei log di audit, esposte via API admin. Rischio GDPR.
  - Fix: **structlog** (stdout JSON) sostituisce fsspec/AsyncFileSystem.
    `_mask_email()` applicato prima di emettere l'evento via structlog — la PII non esiste mai
    in chiaro su disco né nello stream di log. Setting `AUDIT_EMAIL_LOG_LEVEL` controlla il
    livello (`"mask"` default → `jo***@ex***.com`, `"hash"` → HMAC-SHA256, `"none"`).
    L'output è JSON compatibile con AWS CloudWatch, GCP Cloud Logging, Azure Monitor.
    **Write-only**: AuditService non ha metodi di read/delete. L'analisi e retention dei
    log sono demandate al cloud provider. Rimossi tutti i metodi di lettura/scansione
    (`get_logs`, `get_user_login_counts`, `get_event_counts_by_type`, `get_logs_by_date`,
    `delete_old_logs`). Aggiunti `login_count`/`failed_login_count` su `User` per counters
    per-utente visibili in dashboard admin. Gli aggregati temporali (`total_logins_today`)
    restituiscono 0 — vanno queryati dal sistema di log del cloud provider.
  - **Risolto**: AuditService ~80 righe (vs ~224). Solo structlog + masking. Zero fsspec.
    User counters per login nel modello. Output JSON stdout cloud-native.
    Test: 16 test in `tests/unit/test_audit.py` (3 logging, 7 masking, 6 architectural).

- [x] **S11 — No HTTPS enforcement**
  - File: `authglow/main.py`, `.env`, `authglow/core/config.py`, `authglow/middleware/https_enforcement.py`
  - Problema: l'app non forza HTTPS. In produzione dipende dal reverse proxy.
  - Fix:
    1. Aggiunte settings `ENFORCE_HTTPS` (default `true`) e `HTTPS_REDIRECT_STATUS` (default `301`) in `config.py`.
    2. Creato `authglow/middleware/https_enforcement.py` (ASGI puro, stesso pattern di `SecurityHeadersMiddleware`).
       Il middleware controlla prima `X-Forwarded-Proto` header (scenario reverse proxy: nginx/ALB), poi `request.url.scheme`
       (scenario diretto). Attivo solo quando `APP_ENV=production` AND `ENFORCE_HTTPS=true`.
    3. Registrato in `main.py` dopo `MaxBodySizeMiddleware`.
    4. Websocket e scope non-HTTP ignorati.
    5. Documentato in `.env` con sezione `# HTTPS ENFORCEMENT`.
    6. Redirect preserva path e query string della richiesta originale.
  - **Risolto**: Middleware `HttpsEnforcementMiddleware` redirect HTTP→HTTPS in produzione.
    Supporto `X-Forwarded-Proto` per ambienti con reverse proxy (TLS terminato a monte).
    Disattivabile via `ENFORCE_HTTPS=false`.
    Test: 16 unit + 16 integration in `tests/unit/test_https_enforcement.py` e
    `tests/integration/test_https_enforcement.py` (redirect 301/302, no-op in dev,
    X-Forwarded-Proto, enforce_https=false, path+query preservati, produzione case-insensitive).

- [ ] **S12 — Nessun lockout per brute-force API key**
  - File: `authglow/services/api_key.py`
  - Problema: a differenza del login utente, non c'è protezione brute-force sullo scambio API key → JWT.
    Rate limiting globale c'è (`5/min` su `/api/token/api-key`) ma nessun lockout per key.
  - Fix: implementare contatore `failed_api_key_attempts` per key (o per IP) con lockout temporaneo.
    Alternativa: aumentare il rate limit a livello IP con finestre più aggressive.

---

## HIGH — Performance

- [ ] **P1 — Lookup refresh token O(n) glob + bcrypt**
  - File: `authglow/services/refresh_token.py:get_refresh_token()`
  - Problema: per validare UN refresh token, fa glob di TUTTI i file in `refresh_tokens/` e
    bcrypt-compara ogni token. Con migliaia di token attivi, ogni richiesta fa centinaia di bcrypt.
  - Fix: aggiungere un prefix index come per le API key:
    - `refresh_tokens/index/{prefix}.json` → lista di `token_id` candidati.
    - Prendere i primi 12 caratteri del token come prefix.
    - `validate_and_rotate()` carica solo i token_id nel file indice e bcrypt-compara solo quelli.

- [ ] **P2 — Audit log scan completo su ogni query**
  - File: `authglow/services/audit.py` (`get_logs`, `get_event_counts_by_type`, `get_logs_by_date`, `get_user_login_counts`)
  - Problema: ogni query fa glob di TUTTI i file di audit. Su 1 anno di log, centinaia di file JSON.
    `get_user_login_counts()` è particolarmente lento: carica tutti i log, estrae email, conta.
  - Fix: creare indici mensili:
    - `audit/index/YYYY-MM/event_types.json` → mappa `event_type` → conteggio.
    - `audit/index/YYYY-MM/users.json` → mappa `user_email` → conteggio login.
    - Aggiornare gli indici in append quando si scrive un evento.
    - `get_logs` può ancora fare glob ma limitato al mese richiesto (i file sono già organizzati per `YYYY/MM/`).

---

## MEDIUM — Performance

- [ ] **P3 — Verifica password reset token O(n) bcrypt**
  - File: `authglow/services/password_reset.py:verify_token()`
  - Problema: per validare UN token, itera tutti i token di reset e fa bcrypt su ciascuno.
    Con centinaia di token pendenti diventa problematico.
  - Fix: usare `hmac.digest(SECRET_KEY, token_raw, 'sha256')` come lookup key.
    Salvare nei metadati del token: `token_hash = hmac_sha256(token_raw)`.
    Cercare per `token_hash` invece di iterare tutto. Il bcrypt serve ancora per verifica
    (defense-in-depth) ma si fa 1 bcrypt invece di N.

- [ ] **P4 — Admin sessions carica 5x page size**
  - File: `authglow/api/admin.py` (vista admin sessions)
  - Problema: `list_all_tokens(active_only=True, limit=limit*5, offset=0)` carica fino a 5 pagine
    in memoria per filtrare quelli attivi. Spreco di memoria e I/O.
  - Fix: implementare un indice per token attivi:
    - `refresh_tokens/active_index.json` → lista di `token_id` attivi.
    - Aggiornare l'indice a ogni creazione/rotazione/revoca.
    - `list_all_tokens(active_only=True)` usa direttamente l'indice.

- [ ] **P5 — Glob invece di lookup diretto nei consensi**
  - File: `authglow/services/oauth_consent.py:get_user_consent()`
  - Problema: `get_user_consent(user_id, client_id)` fa glob di tutti i consensi invece di
    costruire il percorso deterministico `consents/{user_id}/{client_id}.json`.
  - Fix: usare percorso deterministico. Il glob va bene solo per `get_user_consents()` (lista).
    Per il singolo lookup, costruire il path: `f"consents/{user_id}/{client_id}.json"`.

- [ ] **P6 — Nessun caching layer (Redis/Memcached)**
  - File: globale
  - Problema: ogni richiesta legge da filesystem (o S3/GCS). Con cloud storage la latenza diventa critica.
  - Fix: pianificato per Phase 5. Aggiungere caching per:
    - Configurazione UI (`get_ui_context()`)
    - Chiavi pubbliche JWKS (raramente cambiano)
    - Sessioni OAuth2 attive
    - Lookup utente frequenti (read-through cache)
  - Short-term: `@lru_cache` su `get_ui_context()` e `_ensure_keys_exist()` già esistenti.

- [ ] **P7 — OAuth2ClientStorage I/O non uniforme**
  - File: `authglow/services/oauth_client.py`
  - Problema: usa `Path.open()` + `json` direttamente invece dell'`AsyncFileSystem` wrapper usato
    da tutti gli altri servizi. Nessuna protezione CAS/concorrenza.
  - Fix: allineare a `AsyncFileSystem` come gli altri 12 servizi. Aggiungere supporto versioned
    read/write per proteggere da race condition su update client e rotate secret.

---

## Deployment & Tooling

- [ ] **D3 (ereditato da Phase1) — Attivare type checking / linting**
  - File: `pyproject.toml`
  - Fix: aggiungere config `[tool.mypy]` e `[tool.ruff]` in `pyproject.toml`. Eseguire `mypy authglow/` e `ruff check authglow/`. Fixare gli errori.
    Questo avrebbe intercettato S7 (argomenti errati) staticamente.

- [ ] **D4 — Rotazione chiavi RSA (JWK key rotation)**
  - File: `authglow/services/jwt.py`, `authglow/core/config.py`
  - Problema: le chiavi RSA non hanno meccanismo di rotazione. Se compromesse, tutti i token
    esistenti diventano non validabili senza downtime.
  - Fix: aggiungere `kid` (Key ID) nei JWT. Supportare multiple chiavi con `JWKS.keys[]`.
    La chiave più recente firma, le vecchie verificano. Rotazione periodica (ogni 90 giorni).

- [ ] **D5 — Backup codes: rate limit dedicato**
  - File: `authglow/services/mfa.py`, `authglow/api/mfa.py` e `auth.py`
  - Problema: i tentativi di backup code non hanno rate limiter specifico. 10 tentativi
    (uno per ogni backup code) potrebbero essere provati rapidamente.
  - Fix: aggiungere `@limiter.limit("3/minute")` sull'endpoint MFA verify che accetta backup code,
    con contatore tentativi falliti e cooldown di 30 secondi dopo 3 errori.

---

## Checklist Rapida per Sessione (da compilare)

- [x] S1 — Introspection endpoint auth
- [x] S2 — CSRF protection form
- [x] S3 — Secret key hardening
- [x] S4 — CORS credentials+wildcard fix
- [x] S5 — RSA private key encryption
- [x] S6 — Security headers middleware
- [x] S7 — Bug change_password args
- [x] S8 — Request body size limit
- [x] S9 — Timing side-channel email lookup
- [x] S10 — Audit log PII/GDPR
- [x] S11 — HTTPS enforcement
- [ ] S12 — API key brute-force lockout
- [ ] P1 — Refresh token prefix index
- [ ] P2 — Audit log indici mensili
- [ ] P3 — Password reset HMAC lookup
- [ ] P4 — Admin sessions active_index
- [ ] P5 — Consent lookup deterministico
- [ ] P6 — Caching layer (Phase 5)
- [ ] P7 — OAuth2ClientStorage AsyncFileSystem
- [ ] D3 — mypy + ruff config
- [ ] D4 — JWK key rotation
- [ ] D5 — Backup code rate limit
