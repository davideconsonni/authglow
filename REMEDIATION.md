# AuthGlow Remediation Plan

Questo documento traccia tutti i problemi tecnici e di sicurezza identificati durante la review del codebase. Aggiorna lo stato man mano che procedi.

---

## Legenda Stati

- `pending` — Da iniziare
- `in_progress` — In lavorazione
- `blocked` — Bloccato da dipendenze o decisioni
- `done` — Completato e verificato
- `wontfix` — Deciso di non risolvere

---

## CRITICAL — Sicurezza

| #  | Problema                                                                                                                                                         | File/i coinvolti                                                                                        | Azione richiesta                                                                                                         | Stato   | Note |
|----|------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|---------|------|
| C1 | **JWT scaduti accettati** — `decode_token()` non valida il claim `exp`.                                                                                          | `authglow/services/jwt.py`                                                                              | Aggiunto `verify_exp: True` esplicito in `_decode_token()`, controllo defense-in-depth in `decode_token()` e `decode_id_token()`.        | done |      |
| C2 | **MFA trusted device rotto** — Il fingerprint usa `pwd_context.hash(data)[:64]`, distruggendo l'hash bcrypt. Confronto in `is_device_trusted()` fallisce sempre. | `authglow/services/mfa.py`                                                                              | Sostituito bcrypt truncato con HMAC-SHA256 usando `secret_key` dell'app.                                            | done | Fingerprint ora deterministica, confronto `==` funziona correttamente |
| C3 | **Backup code MFA rotto nell'endpoint standalone** — `code in backup_codes.codes` fallisce perché i codici sono hash bcrypt.                                     | `authglow/api/mfa.py` (verify_mfa_login)                                                                | Sostituito confronto diretto con `mfa_service.verify_user_backup_code()`, come in `auth.py`. Rimossa logica manuale di rimozione codice (gestita dal service). | done |      |
| C4 | **Token endpoint non autentica il client** — Scambio authorization code senza verificare `client_id`/`client_secret`. | `authglow/api/auth.py` (token_endpoint) | Aggiunto autenticazione client per `authorization_code` grant: verifica `client_id` match con auth code, autenticazione obbligatoria per client confidential (form params + Basic Auth), client pubblici richiedono PKCE. | done | RFC 6749 §4.1.3 |
| C5 | **Password hashing difettoso per UTF-8 lunghe** — `encode()[:72]` tronca a byte 72 spezzando caratteri multi-byte, causando collisioni.                                | `authglow/services/password.py`, `authglow/api/password_reset.py`                                  | Aggiunto `_prepare_password_bytes()` con troncamento UTF-8 boundary-safe in `password.py`. Sostituiti 4 chiamate dirette `bcrypt` in `password_reset.py` con `hash_password`/`verify_password`. | done | Collisioni UTF-8 eliminate; test verificano boundary-aware truncation |
| C6 | **Token sensibili usano UUID4** — Non crittograficamente sicuro per bearer tokens.                                                                               | `authglow/models/token.py`, `authglow/models/refresh_token.py`, `authglow/models/email_verification.py`, `authglow/models/session.py`, `authglow/services/session.py`, `authglow/services/oauth2.py` | Sostituito `uuid4()` con `secrets.token_urlsafe(32)` per authorization codes, refresh tokens (token + token_id), email verification tokens, MFA session tokens, consent session tokens. Rimosa import `uuid4` in `oauth2.py`. | done | Esteso scope a MFA session e consent session tokens (anch'essi bearer token sensibili) |

## HIGH — Sicurezza / Affidabilità

| #  | Problema                                                                                      | File/i coinvolti                                 | Azione richiesta                                                                              | Stato   | Note |
|----|-----------------------------------------------------------------------------------------------|--------------------------------------------------|-----------------------------------------------------------------------------------------------|---------|------|
| H1 | **TOTP secrets in chiaro** — `mfa_secret` è testo base32 non cifrato nel DB.                  | `authglow/models/user.py`, `authglow/api/mfa.py` | Cifrare TOTP secret con AES-256-GCM usando chiave derivata dall'app secret prima di salvarlo. | pending |      |
| H2 | **Rate limiter non collegato** — SlowAPI decoratori presenti ma `limiter` non in `app.state`. | `authglow/main.py`                               | De-commentare e collegare correttamente `Limiter` con `get_remote_address` in `app.state`.    | pending |      |
| H3 | **Validazione API key O(n)** — Carica tutte le key e fa bcrypt su ognuna.                     | `authglow/services/api_key.py`                   | Aggiungere indice per prefix (es. prime 8 char del plaintext) per evitare scan completo.      | pending |      |
| H4 | **Setup endpoint senza rate limit** — Race condition + brute force possibile.                 | `authglow/api/setup.py`                          | Aggiungere `@limiter.limit(...)` dopo aver fissato H2, o altra protezione.                    | pending |      |
| H5 | **CORS header parsing bug** — La stringa CSV finisce come singolo elemento.                   | `authglow/main.py:50`                            | Splittare `settings.cors_allowed_headers` su `,` prima di passare a `allow_headers`.          | pending |      |
| H6 | **Passkey registration permette duplicati** — `exclude_credentials` è hardcodato `[]`.        | `authglow/services/passkey.py`                   | Popolare `exclude_credentials` con le passkey esistenti dell'utente.                          | pending |      |
| H7 | **Passkey service: bytes.fromhex su base64url** — Parsing errato del credential_id.           | `authglow/services/passkey.py`                   | Usare `base64url_to_bytes` invece di `bytes.fromhex`.                                         | pending |      |

## MEDIUM — Bug / Architettura

| #  | Problema                                                                                         | File/i coinvolti                                               | Azione richiesta                                                                                | Stato   | Note |
|----|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------|-------------------------------------------------------------------------------------------------|---------|------|
| M1 | **Audit log: filtro event_type usa substring matching** — `"login"` matcha anche `login_failed`. | `authglow/services/audit.py`                                   | Usare confronto esatto o prefix matching strutturato.                                           | pending |      |
| M2 | **JWTService istanziato a livello modulo** — Triggera generazione chiavi all'import.             | `authglow/core/permissions.py`                                 | Usare lazy initialization o dependency injection.                                               | pending |      |
| M3 | **Router oauth2_advanced non montato** — Revocation/introspection irraggiungibili.               | `authglow/main.py`                                             | Aggiungere `include_router(oauth2_advanced_router)`.                                            | pending |      |
| M4 | **Timezone handling inconsistente** — `utcnow()` (naive) vs `now(timezone.utc)` (aware).         | Tutto il codebase                                              | Standardizzare su `datetime.now(timezone.utc)` ovunque.                                         | pending |      |
| M5 | **I/O sincrono in funzioni async** — `fsspec` blocca l'event loop.                               | `authglow/services/storage.py`, `session.py`, `audit.py`, ecc. | Wrappare operazioni fsspec in `asyncio.to_thread()` o usare `run_in_executor`.                  | pending |      |
| M6 | **Race conditions nello storage** — Pattern read-modify-write senza atomicità.                   | `storage.py`, `refresh_token.py`, `oauth2.py`                  | Aggiungere locking (es. file-based lock con fsspec) o usare operazioni atomiche dove possibile. | pending |      |
| M7 | **Admin carica tutto in memoria** — `limit=10000` utenti e log causa OOM.                        | `authglow/api/admin.py`                                        | Paginare correttamente con query offset/limit, non caricare tutto in memoria.                   | pending |      |
| M8 | **Nessun test** — Zero test nel repository.                                                      | —                                                              | Aggiungere almeno test unitari per JWT, OAuth2 flows, MFA, passkey.                             | pending |      |

## MAINTENANCE — Dipendenze & Tooling

| #  | Problema                                                                                                                                | Azione richiesta                                       | Stato   | Note                                                                                                                         |
|----|-----------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| D1 | **Migrare gestione dipendenze a uv compile** — Creato `requirements.in` top-level; `requirements.txt` ora generato da `uv pip compile`. | Aggiornare `requirements.txt` e testare compatibilità. | done    | Per aggiornare: `uv pip compile --upgrade requirements.in -o requirements.txt --python-version 3.13 --python-platform linux` |
| D2 | **Valutare sostituzione passlib** — Passlib 1.7.4 è ormai unmaintained.                                                                 | Considerare `pwdlib`, `argon2-cffi`, o bcrypt diretto. | pending |                                                                                                                              |
| D3 | **Aggiungere type checking / linting** — Assicurarsi che `mypy` e `ruff` passino.                                                       | Aggiungere config in `pyproject.toml` se mancante.     | pending |                                                                                                                              |

---

## Dipendenze da aggiornare

| Pacchetto         | Attuale      | Ultima  | Note                               |
|-------------------|--------------|---------|------------------------------------|
| fastapi           | **0.136.1**  | Lockato |                                    |
| uvicorn           | **0.47.0**   | Lockato |                                    |
| python-multipart  | **0.0.28**   | Lockato |                                    |
| pyjwt             | **2.12.1**   | Lockato |                                    |
| bcrypt            | **5.0.0**    | Lockato | **Breaking con passlib — vedi D2** |
| cryptography      | **48.0.0**   | Lockato |                                    |
| webauthn          | **2.7.1**    | Lockato |                                    |
| fsspec            | **2026.4.0** | Lockato |                                    |
| s3fs              | **2026.4.0** | Lockato |                                    |
| gcsfs             | **2026.5.0** | Lockato |                                    |
| adlfs             | **2026.5.0** | Lockato |                                    |
| pydantic          | **2.13.4**   | Lockato |                                    |
| pydantic-settings | **2.14.1**   | Lockato |                                    |
| python-dotenv     | **1.2.2**    | Lockato |                                    |

---

## Checklist rapida per sessione

- [x] C1 — JWT exp validation
- [x] C2 — MFA trusted device fingerprint
- [x] C3 — MFA backup code fix
- [x] C4 — Token endpoint client auth
- [x] C5 — Password hashing UTF-8 fix
- [x] C6 — Replace UUID4 with secrets.token_urlsafe
- [ ] H1 — Encrypt TOTP secrets
- [ ] H2 — Wire up SlowAPI limiter
- [ ] H3 — API key O(n) fix
- [ ] H4 — Setup endpoint rate limit
- [ ] H5 — CORS headers parsing
- [ ] H6 — Passkey exclude_credentials
- [ ] H7 — Passkey base64url parsing
- [ ] M1 — Audit log exact event_type match
- [ ] M2 — Lazy JWTService init
- [ ] M3 — Mount oauth2_advanced router
- [ ] M4 — Consistent timezone usage
- [ ] M5 — Async fsspec I/O
- [ ] M6 — Storage race conditions
- [ ] M7 — Admin pagination
- [ ] M8 — Add tests
- [ ] D1 — Update dependencies
- [ ] D2 — Evaluate passlib replacement
- [ ] D3 — Add lint/typecheck config
