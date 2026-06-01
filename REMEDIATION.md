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

- [ ] **S2 — Nessuna protezione CSRF sui form POST**
  - File: `authglow/api/auth.py`, `authglow/api/oauth_consent_handler.py`, `authglow/api/mfa.py`, tutti i template HTML
  - Problema: login, consent, MFA verify sono POST senza token anti-CSRF. Un sito malevolo può forzare richieste.
  - Fix: generare `csrf_token` nella GET, inserirlo come hidden field nei form, validarlo nella POST corrispondente.
    Usare `secrets.token_urlsafe(32)` memorizzato in una sessione temporanea file-based con scadenza 30 minuti.

- [ ] **S3 — Secret key deboli / placeholder in `.env`**
  - File: `.env:13-14`
  - Problema: `SECRET_KEY` e `JWT_SECRET_KEY` sono `"your-secret-key-change-in-production-min-32-chars"`.
    Superano il controllo `min_length=32` ma NON sono chiavi crittografiche.
  - Fix: generare chiavi reali con `openssl rand -hex 32`. Aggiungere warning all'avvio se le chiavi contengono "change-in-production".
    NON committare mai `.env` con segreti reali.

- [ ] **S4 — CORS misconfiguration: credentials + wildcard headers**
  - File: `.env:90,96`, `authglow/core/config.py`
  - Problema: `CORS_ALLOW_CREDENTIALS=true` + `CORS_ALLOWED_HEADERS=*`. I browser rifiutano questa combinazione
    (viola lo standard fetch). Headers `*` viene ignorato quando `credentials=true`.
  - Fix: specificare header esplicitamente (`Authorization, Content-Type, X-Requested-With`) oppure
    impostare `CORS_ALLOW_CREDENTIALS=false` se non si usano cookie cross-origin. Aggiungere un warning
    di startup se la combinazione è rilevata.

---

## HIGH — Sicurezza

- [ ] **S5 — Chiave privata RSA in chiaro su disco**
  - File: `authglow/core/config.py`, `data/keys/private_key.pem`
  - Problema: `_generate_rsa_keys()` in `config.py` genera chiavi RSA 2048-bit e le salva senza cifratura
    in `data/keys/`. Se il filesystem viene compromesso, l'attaccante può firmare token arbitrari.
  - Fix opzioni:
    1. Cifrare la private key a riposo con AES-256-GCM usando `SECRET_KEY` (stesso schema di `crypto.py`).
    2. In cloud, usare KMS (AWS KMS, GCP KMS, Azure Key Vault).
    3. Caricare chiave da variabili d'ambiente invece che da file.
    4. Short-term: documentare che `data/keys/` deve avere permessi `0600`.

- [ ] **S6 — Security headers assenti**
  - File: `authglow/main.py`
  - Problema: nessun middleware che aggiunge header di sicurezza.
  - Fix: aggiungere middleware (o usare libreria come `secure`) per:
    - `Content-Security-Policy`: `default-src 'self'`
    - `X-Frame-Options`: `DENY`
    - `X-Content-Type-Options`: `nosniff`
    - `Strict-Transport-Security`: `max-age=31536000; includeSubDomains` (solo in produzione)
    - `Referrer-Policy`: `strict-origin-when-cross-origin`
    - `X-XSS-Protection`: `0` (deprecato, CSP lo sostituisce)

- [ ] **S7 — Bug `change_password`: argomenti errati a `send_password_changed_alert`**
  - File: `authglow/services/user_profile.py`
  - Problema: chiama `self.security_service.send_password_changed_alert(user.email, user.first_name or "User", ip_address)`
    ma il metodo in `security_notifications.py` si aspetta `(user: User, ip_address: str)`.
    Causa errore runtime quando l'alert viene inviato.
  - Fix: passare `(user, ip_address)` invece di `(user.email, user.first_name or "User", ip_address)`.

- [ ] **S8 — Nessun limite dimensione body richieste**
  - File: `authglow/main.py`
  - Problema: FastAPI/Starlette non impone limiti espliciti. Un attaccante può inviare payload enormi.
  - Fix: aggiungere `request.max_body_size` o middleware che limita `Content-Length` a ~10 MB.
    Opzioni: Starlette `MaximumContentLengthMiddleware` o `nginx` a monte.

---

## MEDIUM — Sicurezza

- [ ] **S9 — Timing side-channel su lookup email**
  - File: `authglow/services/storage.py:get_user_by_email()`
  - Problema: il lookup via `email_index.json` non è constant-time. Un attaccante potrebbe dedurre
    l'esistenza di un'email misurando i tempi di risposta.
  - Fix: parzialmente mitigato dal rate limiting. Per una protezione completa, usare un tempo
    di risposta costante indipendentemente dal risultato (es. aggiungere un `await asyncio.sleep(random_ms)`
    o fare sempre hash lookup anche quando l'email non esiste).

- [ ] **S10 — Audit log contiene PII queryabile**
  - File: `authglow/services/audit.py`, `authglow/api/admin.py`
  - Problema: email in chiaro nei log di audit, esposte via API admin. Rischio GDPR.
  - Fix:
    1. Aggiungere retention policy configurabile (`AUDIT_LOG_RETENTION_DAYS=365`).
    2. Opzionalmente pseudonimizzare (hash dell'email con `SECRET_KEY`) per i log più vecchi di X giorni.
    3. Documentare la necessità di un DPA se usato in produzione EU.

- [ ] **S11 — No HTTPS enforcement**
  - File: `authglow/main.py`, `.env`
  - Problema: l'app non forza HTTPS. In produzione dipende dal reverse proxy (nginx/ALB).
  - Fix:
    1. In produzione: middleware `HTTPSRedirectMiddleware` condizionale su `APP_ENV=production`.
    2. Documentare che in development si usa HTTP, in produzione serve reverse proxy con TLS.

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
- [ ] S2 — CSRF protection form
- [ ] S3 — Secret key hardening
- [ ] S4 — CORS credentials+wildcard fix
- [ ] S5 — RSA private key encryption
- [ ] S6 — Security headers middleware
- [ ] S7 — Bug change_password args
- [ ] S8 — Request body size limit
- [ ] S9 — Timing side-channel email lookup
- [ ] S10 — Audit log PII/GDPR
- [ ] S11 — HTTPS enforcement
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
