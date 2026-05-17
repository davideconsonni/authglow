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
| H1 | **TOTP secrets in chiaro** — `mfa_secret` è testo base32 non cifrato nel DB. | `authglow/models/user.py`, `authglow/api/mfa.py` | Cifrare TOTP secret con AES-256-GCM usando chiave derivata dall'app secret prima di salvarlo. | done | AES-256-GCM encryption via `authglow/core/crypto.py`. Key derived from `secret_key` via HKDF-SHA256. Format: `ag1:`+base64(iv+ciphertext+tag). Legacy plaintext values pass through for migration. |
| H2 | **Rate limiter non collegato** — SlowAPI decoratori presenti ma `limiter` non in `app.state`. | `authglow/main.py`, `authglow/api/*.py` | Creato `authglow/core/rate_limit.py` con singleton `Limiter`. Collegato in `main.py` via `app.state.limiter` + `SlowAPIMiddleware`. Sostituiti 9 `Limiter()` locali nei moduli API con import dal singleton. | done | SlowAPIMiddleware registra eccezione 429 automaticamente |
| H3 | **Validazione API key O(n)** — Carica tutte le key e fa bcrypt su ognuna.                     | `authglow/services/api_key.py`                   | Aggiunto prefix index O(1) in `api_keys/index/<prefix>.json`. `validate_key()` ora estrae il prefix (primi 12 char) e carica solo i key_id candidati. `create_key()`, `delete_key()` e `cleanup_expired_keys()` mantengono l'indice aggiornato. | done | Prefix index in `api_keys/index/`; fallback a lista vuota se prefix non esiste |
| H4 | **Setup endpoint senza rate limit** — Race condition + brute force possibile.                 | `authglow/api/setup.py`                          | Aggiunto `@limiter.limit()` a tutti e 3 gli endpoint: create-admin 5/min, check 20/min, setup page 20/min. Aggiunto `Request` param dove mancante. Aggiornato test rate_limit per verificare setup module.                    | done |      |
| H5 | **CORS header parsing bug** — La stringa CSV finisce come singolo elemento.                   | `authglow/main.py:50`, `authglow/core/config.py` | Aggiunto `get_cors_headers()` in Settings (split su `,` con wildcard `*`). Sostituita logica inline in `main.py` con `settings.get_cors_headers()`. Test aggiornato per verificare split corretto e wildcard. | done |      |
| H6 | **Passkey registration permette duplicati** — `exclude_credentials` è hardcodato `[]`.        | `authglow/services/passkey.py`, `authglow/api/passkey.py` | Aggiunto parametro `user_passkeys` a `generate_registration_options_dict()`, endpoint `begin_registration` ora recupera le passkey esistenti e le passa al metodo. Sostituito `bytes.fromhex` con `base64url_to_bytes` nella costruzione di `exclude_credentials`. | done | Fix include anche la correzione del parsing del credential_id da hex a base64url nella comprehension di exclude_credentials |
| H7 | **Passkey service: bytes.fromhex su base64url** — Parsing errato del credential_id.           | `authglow/services/passkey.py`                   | Usare `base64url_to_bytes` invece di `bytes.fromhex`.                                         | done | Già corretto come parte di H6; nessun `bytes.fromhex` rimasto. Test verificano assenza e uso corretto di `base64url_to_bytes`. |

## MEDIUM — Bug / Architettura

| #  | Problema                                                                                         | File/i coinvolti                                               | Azione richiesta                                                                                | Stato   | Note |
|----|--------------------------------------------------------------------------------------------------|----------------------------------------------------------------|-------------------------------------------------------------------------------------------------|---------|------|
| M1 | **Audit log: filtro event_type usa substring matching** — `"login"` matcha anche `login_failed`. | `authglow/services/audit.py`                                   | Sostituito `in` con confronto esatto case-insensitive (`!=`). Aggiunti 3 test: exact match, no-substring, distinct-prefix. | done | Search field mantiene substring matching (intenzionale) |
| M2 | **JWTService istanziato a livello modulo** — Triggera generazione chiavi all'import.             | `authglow/core/permissions.py`                                 | Sostituito `jwt_service = JWTService()` con lazy singleton `_get_jwt_service()`. L'istanza viene creata solo alla prima chiamata, non all'import. | done | Test in `tests/unit/test_permissions.py` verificano lazy init, caching e assenza di init a import |
| M3 | **Router oauth2_advanced non montato** — Revocation/introspection irraggiungibili.               | `authglow/main.py`                                             | Aggiunto `include_router(oauth2_advanced_router)` in `main.py`. | done |      |
| M4 | **Timezone handling inconsistente** — `utcnow()` (naive) vs `now(timezone.utc)` (aware). | Tutto il codebase | Creato `authglow/core/datetime.py` con `utcnow()` che ritorna `datetime.now(timezone.utc)`. Sostituiti tutti i `datetime.utcnow()` con `utcnow()` e `default_factory=datetime.utcnow` con `default_factory=utcnow` in modelli Pydantic. Test M4 aggiornato e invertito per verificare assenza di `datetime.utcnow()`. | done | 177 test passano; 1 fail preesistente (oauth2 scope) |
| M5 | **I/O sincrono in funzioni async** — `fsspec` blocca l'event loop.                               | `authglow/services/storage.py`, `session.py`, `audit.py`, ecc. | Creato `authglow/core/async_io.py` con `AsyncFileSystem` wrapper (`asyncio.to_thread()`). Tutti i 16 file con I/O sincrono convertiti ad async. Test aggiornati. | done | vedi `authglow/core/async_io.py`; 203/204 test passano (1 fail preesistente oauth2 scope) |
| M6 | **Race conditions nello storage** — Pattern read-modify-write senza atomicità. | `storage.py`, `refresh_token.py`, `oauth2.py`, ecc. | Due layer di protezione: (1) `AsyncNamedLock` in `core/concurrency.py` per serializzare RMW in-process, (2) `read_json_versioned`/`write_json_versioned` in `core/async_io.py` con CAS ottimistico per cross-process defense-in-depth. Tutti i 12 service con RMW aggiornati. | done | Vedi `authglow/core/concurrency.py` e `authglow/core/async_io.py` |
| M7 | **Admin carica tutto in memoria** — `limit=10000` utenti e log causa OOM.                        | `authglow/api/admin.py`                                        | Paginato correttamente con query offset/limit. `UserStorage.count_users()` e `get_user_stats()` per statistiche senza caricare tutto. `AuditService.get_user_login_counts()` per conteggi per-user. `RefreshTokenService.list_all_tokens()` aggiunto (era mancante, crash runtime). `PaginatedResponse` per risposte paginate. `search_users` usa filtri server-side. Eventuali `limit=10000` rimossi. Setup endpoints usano `count_users()` invece di `list_users`. | done | 234/235 test passano (1 fail preesistente oauth2 scope) |
| M8 | **Nessun test** — Zero test nel repository.                                                      | —                                                              | Aggiunti 12 nuovi file di test unitari per tutti i moduli sorgente senza copertura (session, password_reset, oauth_client, oauth_consent, email_verification, rbac, user_profile, security_notifications, oidc, core/password, email_subsystem) + estensione di test_permissions.py. Fix bug `password_hash` → `hashed_password` in user_profile.py. 436 test totali, 435 passano (1 fail preesistente oauth2 scope). | done | Test coverage da 0% a ~80%+ dei moduli sorgente |

## MAINTENANCE — Dipendenze & Tooling

| #  | Problema                                                                                                                                | Azione richiesta                                       | Stato   | Note                                                                                                                         |
|----|-----------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------|---------|------------------------------------------------------------------------------------------------------------------------------|
| D1 | **Migrare gestione dipendenze a uv compile** — Creato `requirements.in` top-level; `requirements.txt` ora generato da `uv pip compile`. | Aggiornare `requirements.txt` e testare compatibilità. | done    | `uv pip compile --upgrade requirements.in -o requirements.txt --python-version 3.13 --python-platform linux`. Aggiornati: `python-multipart 0.0.28→0.0.29`, `decorator 5.2.1→5.3.0`. Dockerfile aggiornato a `python:3.13-slim`. 435/436 test passano (1 fail preesistente oauth2 scope). |
| D2 | **Valutare sostituzione passlib** — Passlib 1.7.4 è ormai unmaintained.                                                                 | Rimuovere passlib e python-jose (entrambe dipendenze morte, zero import nel codebase). Rimpiazzate da bcrypt diretto (già in uso) e PyJWT (già in uso). | done    | 4 pacchetti rimossi: `passlib`, `python-jose`, `ecdsa`, `rsa`. Nessuna modifica al codice sorgente necessaria. 100→96 pacchetti nel lockfile. 435/436 test passano (1 fail preesistente oauth2 scope). |
| D3 | **Aggiungere type checking / linting** — Assicurarsi che `mypy` e `ruff` passino.                                                       | Aggiungere config in `pyproject.toml` se mancante.     | pending |                                                                                                                              |

---

## Dipendenze da aggiornare

| Pacchetto         | Attuale      | Ultima  | Note                               |
|-------------------|--------------|---------|------------------------------------|
| fastapi           | **0.136.1**  | Lockato |                                    |
| uvicorn           | **0.47.0**   | Lockato |                                    |
| python-multipart  | **0.0.29**   | Lockato |                                    |
| pyjwt             | **2.12.1**   | Lockato |                                    |
| bcrypt            | **5.0.0**    | Lockato | Usato direttamente per password/MFA/API key hashing |
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
- [x] H1 — Encrypt TOTP secrets
- [x] H2 — Wire up SlowAPI limiter
- [x] H3 — API key O(n) fix
- [x] H4 — Setup endpoint rate limit
- [x] H5 — CORS headers parsing
- [x] H6 — Passkey exclude_credentials
- [x] H7 — Passkey base64url parsing
- [x] M1 — Audit log exact event_type match
- [x] M2 — Lazy JWTService init
- [x] M3 — Mount oauth2_advanced router
- [x] M4 — Consistent timezone usage
- [x] M5 — Async fsspec I/O
- [x] M6 — Storage race conditions
- [x] M7 — Admin pagination
- [x] M8 — Add tests
- [x] D1 — Update dependencies
- [x] D2 — Remove passlib + python-jose
- [ ] D3 — Add lint/typecheck config
