# AuthGlow — OAuth 2.0 / OIDC Conformance Remediation Plan

> Roadmap completa dei fix necessari per portare AuthGlow alla massima conformance con OAuth 2.0 / OIDC Core 1.0.
> Ogni checkbox è un'unità di lavoro atomica, ordinata per priorità e raggruppata in workstream tematici.
>
> **Origine**: assessment read-only del 2026-06-13, codice in `backend/authglow/`.
> **Target**: massima conformance (OAuth 2.0 Security BCP, OIDC Core 1.0, RFC 7591/7592/8628, FAPI-aligned quando possibile).
> **Test plan complementare**: [`docs/CONFORMANCE_TEST_PLAN.md`](CONFORMANCE_TEST_PLAN.md).

---

## Legenda

- 🔴 **P0** — Blocker di produzione (security / spec violation)
- 🟠 **P1** — Importante per essere un OIDC provider rispettabile
- 🟡 **P2** — Migliorativo / nice-to-have
- 🟢 **DONE** — Spuntare quando completato e testato
- **[file:line]** — Riferimento al codice esistente da toccare

---

## Workstream A — Security: JWT Audience Validation 🟢

L'audience non è mai verificato. Su un ID token, questo è un violation diretto di OIDC Core §3.1.3.7 e abilita token confusion attack cross-client.

> **Stato**: completato 2026-06-14. 12/12 task chiusi. 154 test passati, ruff+mypy clean.

- [x] **A.1** Aggiungere campo `aud` (claim singolo) e `azp` agli access token OAuth2 in `services/jwt.py:175-188` quando emessi per un client OAuth2 (non per il flow cookie-first). [services/jwt.py:175-188]
- [x] **A.2** Aggiungere parametro `audience: Optional[str] = None` a `create_access_token()` per forzare l'audience quando il token è emesso per un client. [services/jwt.py:158-189]
- [x] **A.3** Modificare `create_id_token()` per richiedere `aud=client_id` e impostare `azp=client_id` (auto se aud singolo, mandatory se aud multiplo). [services/jwt.py:267-303]
- [x] **A.4** Modificare `_decode_token()` in modo che la verifica di `aud` sia **configurabile**: True obbligatorio quando il chiamante passa `expected_aud`. Cambiare l'opzione fissa `verify_aud: False` a `verify_aud: True` con un parametro dinamico. [services/jwt.py:118-156]
- [x] **A.5** Aggiungere parametro `expected_aud: Optional[str] = None` a `decode_token()` e propagarlo. [services/jwt.py:222-265]
- [x] **A.6** Aggiungere parametro `expected_aud: str` (required) a `decode_id_token()`. Se non corrisponde, ritornare `None`. [services/jwt.py:305-313]
- [x] **A.7** Aggiornare `api/auth.py:token_endpoint` grant `authorization_code` per passare `expected_aud=auth_code.client_id` quando decodifica il refresh. [api/auth.py:444-607]
- [x] **A.8** Aggiornare `api/auth.py:token_endpoint` grant `refresh_token` per passare `expected_aud=client_id` quando decodifica per audit. [api/auth.py:638-679]
- [x] **A.9** Aggiornare `api/oidc.py:userinfo` per passare `expected_aud=client_id` (se noto dal token) nella decodifica. [api/oidc.py:155-201]
- [x] **A.10** Aggiornare `api/oidc.py:logout_get` per passare `expected_aud=client_id` nella decodifica di `id_token_hint`. [api/oidc.py:204-277]
- [x] **A.11** Aggiornare `api/oauth2_advanced.py:introspect_token` per verificare che `aud` del token corrisponda al `client_id` che esegue l'introspection. [api/oauth2_advanced.py:121-214]
- [x] **A.12** Aggiungere test in `tests/unit/test_jwt_audience.py` che verifichi:
  - ID token con aud diverso dal client → rifiutato
  - Access token emesso per client A non decodificabile da client B
  - `azp` claim presente e corretto

## Workstream B — Security: PKCE Enforcement 🟠

PKCE è richiesto solo per client pubblici. OAuth 2.0 Security BCP raccomanda PKCE per **tutti** i client.

- [ ] **B.1** Aggiungere `enforce_pkce: bool = True` a `Settings` (con default sicuro). [core/config.py:218-548]
- [ ] **B.2** Aggiungere `enforce_pkce: bool = True` al modello `OAuth2Client` (default True per nuovi client). [models/oauth_client.py:12-58]
- [ ] **B.3** In `api/auth.py:authorize_post`, rifiutare l'auth request con `code_challenge` mancante **se** `enforce_pkce` è True a livello globale o per il client. [api/auth.py:234-441]
- [ ] **B.4** In `api/oidc.py:register_oauth_client` (DCR), forzare `require_pkce=True` per i client pubblici e documentare/enforce per confidential. [api/oidc.py:354-449]
- [ ] **B.5** Migrazione: in `migrate_pkce_default.py` (script one-shot), settare `require_pkce=True` per tutti i client esistenti. Loggare audit. [scripts/]
- [ ] **B.6** Aggiungere test in `tests/unit/test_pkce_enforcement.py` che verifichi:
  - Client con `enforce_pkce=True` rifiuta auth request senza `code_challenge`
  - Client con `enforce_pkce=False` (legacy) accetta auth request senza `code_challenge`
  - DCR genera client con `require_pkce=True` di default

## Workstream C — Security: CSRF Protection su /oauth2/authorize 🟠

L'endpoint `/oauth2/authorize` POST-only accetta form senza CSRF token. Con un cookie di sessione, un attacker può forzare emissione di auth code verso un client malevolo.

- [ ] **C.1** Verificare l'esistenza e capire il funzionamento di `services/csrf.py` (lettura del file).
- [ ] **C.2** In `api/auth.py:authorize_post`, rilevare se l'utente è autenticato via cookie di sessione (già fatto a `api/auth.py:281-289`). Se sì, richiedere un CSRF token. [api/auth.py:277-365]
- [ ] **C.3** Definire modello `AuthorizeForm` con campi: `email`, `password`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`, `csrf_token`. [api/auth.py:234-251]
- [ ] **C.4** Generare un CSRF token server-side quando l'utente arriva sulla pagina di login (endpoint `GET /api/oauth2/authorize` con rendering template).
- [ ] **C.5** Validare il CSRF token nel POST `/api/oauth2/authorize` se l'utente è già loggato via cookie. [api/auth.py:234-441]
- [ ] **C.6** Audit log di tutti i fallimenti CSRF con `event_type="csrf_token_mismatch"`, severity high.
- [ ] **C.7** Aggiungere test in `tests/integration/test_csrf.py` con casi:
  - POST senza CSRF token quando sessione attiva → 403
  - POST con CSRF token valido → 200
  - POST con CSRF token scaduto → 403

## Workstream D — Security: post_logout_redirect_uri Validation 🟠

L'endpoint `/oauth2/logout` permette redirect a qualsiasi URL in dev e a localhost in produzione, trasformando l'AS in open redirector.

- [ ] **D.1** In `api/oidc.py:logout_get`, separare nettamente il path dev-mode vs production-mode: in dev loggare warning, in production confrontare `post_logout_redirect_uri` con `client.redirect_uris`. [api/oidc.py:247-260]
- [ ] **D.2** Introdurre setting `oidc_strict_logout_redirect: bool = True` (default production-safe) in `Settings`. [core/config.py:218-548]
- [ ] **D.3** Aggiungere `allowed_post_logout_redirect_uris: List[str]` al modello `OAuth2Client` (separato da `redirect_uris`, come raccomandato da RP-Initiated Logout spec). [models/oauth_client.py:12-58]
- [ ] **D.4** Validare `post_logout_redirect_uri` contro `allowed_post_logout_redirect_uris` con strict equality. [api/oidc.py:247-260]
- [ ] **D.5** Migration: per client esistenti senza `allowed_post_logout_redirect_uris`, in production rifiutare ogni `post_logout_redirect_uri`. Loggare warning.
- [ ] **D.6** Aggiungere test in `tests/unit/test_logout_redirect.py`:
  - Production + client senza `allowed_post_logout_redirect_uris` + redirect qualsiasi → 400
  - Production + client con `allowed_post_logout_redirect_uris` + redirect match → 303
  - Dev mode + redirect localhost → 303 con warning loggato

## Workstream E — Discovery: Rimozione Implicit Grant 🟠

Il discovery annuncia `implicit` grant e response types correlati, ma l'endpoint non li implementa. Client OIDC generici si auto-configurano male.

- [ ] **E.1** In `api/oidc.py:openid_configuration`, rimuovere `"implicit"` da `grant_types_supported`. [api/oidc.py:56-61]
- [ ] **E.2** Rimuovere `"token"`, `"id_token"`, `"code token"`, `"code id_token"`, `"token id_token"`, `"code token id_token"` da `response_types_supported`. Mantenere solo `"code"`. [api/oidc.py:46-54]
- [ ] **E.3** Aggiungere `code_challenge_methods_supported: ["S256"]` (già presente, verificare). [api/oidc.py:93]
- [ ] **E.4** Aggiornare il modello `OAuth2Client.grant_types` validator per rifiutare `"implicit"` in nuovi client. [models/oauth_client.py:22]
- [ ] **E.5** Migration: per client esistenti con `grant_types` che includono `"implicit"`, rimuovere l'entry e loggare audit.
- [ ] **E.6** Aggiungere test in `tests/unit/test_discovery.py`:
  - `grant_types_supported` non contiene `"implicit"`
  - `response_types_supported` contiene solo `"code"`
  - `code_challenge_methods_supported` contiene solo `"S256"`

## Workstream F — OIDC Core: amr / acr Claims 🟠

L'ID Token non emette `amr` (Authentication Methods References) né `acr` (Authentication Context Class Reference). Questi claim sono richiesti se l'RP vuole distinguere flussi MFA vs password-only.

- [ ] **F.1** Aggiungere `amr: Optional[List[str]]` e `acr: Optional[str]` al modello `IDTokenClaims`. [models/oidc.py:9-28]
- [ ] **F.2** Definire mapping statico dei livelli ACR:
  - `"0"` = no auth
  - `"1"` = password
  - `"2"` = password + TOTP/backup code
  - `"3"` = password + WebAuthn/Passkey
  - In `services/oidc.py` o nuovo `services/acr.py`. [services/oidc.py:1-191]
- [ ] **F.3** Tracciare `auth_methods` durante il login: aggiungere campo `auth_methods: List[str]` al modello `User` o creare tabella `user_auth_methods` (o equivalente file). [services/storage.py:1-30]
- [ ] **F.4** In `services/login_history.py:record_login` aggiungere campo `auth_methods` oppure aggiungere una nuova funzione `record_auth_method(user_id, method)`.
- [ ] **F.5** In `api/auth.py:login_for_access_token`, dopo auth password riuscita, chiamare `record_auth_method(user.id, "pwd")`. [api/auth.py:686-842]
- [ ] **F.6** In `api/auth.py:oauth2_mfa_verify`, dopo verifica TOTP riuscita, chiamare `record_auth_method(user.id, "totp")` (o "webauthn" per passkey). [api/auth.py:1111-1186]
- [ ] **F.7** In `api/auth.py:passkey` (da ispezionare), aggiungere `record_auth_method(user.id, "webauthn")` dopo auth riuscita.
- [ ] **F.8** In `services/jwt.py:create_id_token`, leggere gli `auth_methods` dell'utente e calcolare `amr` (es. `["pwd", "totp"]`) e `acr` (es. `"2"`). [services/jwt.py:267-303]
- [ ] **F.9** Aggiungere `acr` e `amr` a `claims_supported` nel discovery. [api/oidc.py:65-92]
- [ ] **F.10** Aggiungere test in `tests/unit/test_id_token_claims.py`:
  - Login con solo password → `acr="1"`, `amr=["pwd"]`
  - Login con password + TOTP → `acr="2"`, `amr=["pwd", "totp"]`
  - Login con passkey → `acr="3"`, `amr=["webauthn"]`

## Workstream G — OIDC Core: prompt Parameter 🟠

Il parametro `prompt` (`none`, `login`, `consent`, `select_account`) non è implementato. Critico per SSO silent re-auth.

- [ ] **G.1** Estendere il modello Pydantic dei parametri di `authorize_post` con `prompt: Optional[str] = Form(None)`. [api/auth.py:234-251]
- [ ] **G.2** Validare `prompt`: valori ammessi = `none`, `login`, `consent`, `select_account`. Multipli separati da spazio.
- [ ] **G.3** Gestire `prompt=none`:
  - Se utente NON autenticato e client NON ha accesso a credenziali → errore `interaction_required` (OIDC §3.1.2.1)
  - Se utente autenticato → procedi con auth code (no UI)
  - Restituire 302 diretto al `redirect_uri` con `code` (o errore OIDC) — non JSON
- [ ] **G.4** Gestire `prompt=login`:
  - Forzare re-autenticazione anche se cookie di sessione valido
  - Pulire il cookie di sessione prima di procedere
- [ ] **G.5** Gestire `prompt=consent`:
  - Saltare il check di consenso esistente
  - Mostrare sempre la consent screen
- [ ] **G.6** Gestire `prompt=select_account`:
  - Mostrare selettore account (placeholder per ora, può essere solo il proprio utente)
- [ ] **G.7** Per `prompt=none`, ritornare errori OIDC-style al `redirect_uri` con `error=login_required` / `error=consent_required` / `error=interaction_required` + `state`.
- [ ] **G.8** Aggiungere test in `tests/integration/test_prompt_param.py` con casi:
  - `prompt=none` + utente non autenticato → redirect con `error=login_required`
  - `prompt=none` + utente autenticato → redirect con `code`
  - `prompt=login` + utente autenticato → forza re-login
  - `prompt=consent` + consenso già dato → mostra comunque consent screen

## Workstream H — OIDC Core: max_age Parameter 🟠

Il parametro `max_age` non è implementato. Combinato con `auth_time`, permette al client di richiedere re-auth dopo N secondi.

- [ ] **H.1** Estendere `authorize_post` con `max_age: Optional[int] = Form(None)`. [api/auth.py:234-251]
- [ ] **H.2** In `services/jwt.py:create_id_token`, recuperare l'`auth_time` reale della sessione corrente (non `user.last_login`). Tracciarlo in `user_sessions` o passarlo via `mfa_session`. [services/jwt.py:267-303]
- [ ] **H.3** Se `max_age` è specificato e `auth_time` è più vecchio di `max_age` secondi, trattare come `prompt=login`. [api/auth.py:234-441]
- [ ] **H.4** Aggiungere test in `tests/integration/test_max_age.py`:
  - `max_age=0` → sempre re-login
  - `max_age=3600` + auth 1h fa → re-login
  - `max_age=3600` + auth 30min fa → no re-login

## Workstream I — OIDC Core: id_token_hint Login 🟠

Quando l'utente atterra su `/oauth2/authorize` con un `id_token_hint`, dovrebbe essere pre-identificato.

- [ ] **I.1** Estendere `authorize_post` con `id_token_hint: Optional[str] = Form(None)`. [api/auth.py:234-251]
- [ ] **I.2** Decodificare l'`id_token_hint` (con `verify_aud` se possibile) e usare il `sub` per pre-popolare il campo email nella login UI. [api/auth.py:277-365]
- [ ] **I.3** Aggiungere test in `tests/unit/test_id_token_hint.py`:
  - POST con id_token_hint valido + sub noto → login pre-popolato
  - POST con id_token_hint invalido → ignorato (non errore)

## Workstream J — Token Blacklist Persistente 🟠

Il token blacklist è in-process. Multi-instance deployment non condivide le revoche.

- [ ] **J.1** Ispezionare `core/token_blacklist.py` per capire l'implementazione corrente.
- [ ] **J.2** Aggiungere `blacklist_backend: str = "memory"` a `Settings` (valori: `memory`, `storage`). [core/config.py:218-548]
- [ ] **J.3** Implementare `StorageTokenBlacklist` che persiste in `data/blacklist/{jti}.json` con TTL = `exp - now`. [core/token_blacklist.py]
- [ ] **J.4** Modificare `token_blacklist()` factory per selezionare backend da setting. [core/token_blacklist.py]
- [ ] **J.5** Aggiungere cleanup job (in `RefreshTokenService.cleanup_expired_tokens` o nuovo `cleanup_blacklist`) che rimuove entry scadute.
- [ ] **J.6** Aggiungere test in `tests/integration/test_token_blacklist.py`:
  - Revoca su instance A visibile da instance B (con storage backend condiviso)
  - Entry scadute rimosse automaticamente

## Workstream K — OIDC: DCR Management (RFC 7592) 🟡

Endpoint `/oauth2/register/{client_id}` per GET/PUT/DELETE non esiste.

- [ ] **K.1** Definire modello `ClientUpdateRequest` con campi opzionali di `OAuth2Client`. [api/oidc.py:311-332]
- [ ] **K.2** Implementare `GET /oauth2/register/{client_id}` che ritorna il client config (escludendo `client_secret`). [api/oidc.py:354-449]
- [ ] **K.3** Implementare `PUT /oauth2/register/{client_id}` per update. Richiede autenticazione del client (HTTP Basic con segreto). [api/oidc.py]
- [ ] **K.4** Implementare `DELETE /oauth2/register/{client_id}` per delete. Richiede autenticazione del client. [api/oidc.py]
- [ ] **K.5** Aggiungere `registration_management_endpoint` o `registration_endpoint_auth_methods_supported` al discovery.
- [ ] **K.6** Aggiungere test in `tests/integration/test_dcr_management.py`:
  - GET con client_id/secret validi → 200 con config
  - PUT con client_id/secret validi → 200 con config aggiornata
  - DELETE con client_id/secret validi → 204

## Workstream L — OIDC: Back-Channel e Front-Channel Logout 🟡

L'AS non supporta nessuno dei due meccanismi OIDC di logout propagato.

- [ ] **L.1** Aggiungere `sid: str` (Session ID) claim all'ID token. [services/jwt.py:267-303]
- [ ] **L.2** Tracciare `sid` in `SessionService` per ogni sessione attiva. [services/session.py:1-100]
- [ ] **L.3** Aggiungere `backchannel_logout_uri: Optional[str]` e `backchannel_logout_session_required: bool` al modello `OAuth2Client`. [models/oauth_client.py:12-58]
- [ ] **L.4** Implementare `POST /oauth2/backchannel-logout` che:
  - Valida il logout token firmato dall'AS
  - Invia POST a `backchannel_logout_uri` di tutti i client attivi per la sessione
- [ ] **L.5** Aggiungere `frontchannel_logout_uri: Optional[str]` e `frontchannel_logout_session_required: bool` al modello `OAuth2Client`. [models/oauth_client.py]
- [ ] **L.6** In `/oauth2/logout` (RP-Initiated), iniettare un `<iframe src="{frontchannel_logout_uri}?iss=...&sid=...">` nella risposta HTML. [api/oidc.py:204-308]
- [ ] **L.7** Aggiungere `backchannel_logout_supported: true` e `frontchannel_logout_supported: true` al discovery (se implementati).
- [ ] **L.8** Aggiungere test in `tests/integration/test_backchannel_logout.py` e `test_frontchannel_logout.py`.

## Workstream M — OIDC: c_hash / at_hash Claims 🟡

Opzionale ma raccomandato per client confidential che vogliono validare che l'access token / code sia stato emesso per lo stesso client.

- [ ] **M.1** In `services/jwt.py:create_id_token`, calcolare `at_hash` se emesso insieme a un access token. Usare `hashlib.sha256(access_token).digest()[:16]`, poi `base64url` no padding. [services/jwt.py:267-303]
- [ ] **M.2** Aggiungere `c_hash` per il flusso `code id_token` (non implementato in AuthGlow attualmente, ma predisporre).
- [ ] **M.3** Aggiungere test in `tests/unit/test_id_token_at_hash.py`:
  - ID token emesso con access token → `at_hash` presente e corretto
  - ID token emesso senza access token (es. `response_type=id_token`) → `at_hash` assente

## Workstream N — UserInfo Cleanup 🟡

Claim `permissions` e `roles` non sono dichiarati nel discovery. Claim `address` mai popolato.

- [ ] **N.1** Rimuovere `permissions` e `roles` custom claim dal UserInfo, oppure dichiararli in `claims_supported` con descrizione. [api/oidc.py:155-201]
- [ ] **N.2** Aggiungere campo `address: Optional[dict]` al modello `User`. [models/user.py:1-100]
- [ ] **N.3** Popolare `address` in `services/oidc.py:get_user_info` se `address` è negli scopes. [services/oidc.py:17-98]
- [ ] **N.4** Aggiungere form/profile page per gestire l'indirizzo dell'utente.
- [ ] **N.5** Aggiungere test in `tests/unit/test_userinfo_claims.py`:
  - `address` scope + user con address → claim popolato
  - `address` scope + user senza address → claim assente

## Workstream O — Rate Limiting Mancante 🟡

Diversi endpoint non hanno rate limit.

- [ ] **O.1** Aggiungere `@limiter.limit("60/minute")` a `/.well-known/openid-configuration`. [api/oidc.py:28-97]
- [ ] **O.2** Aggiungere `@limiter.limit("60/minute")` a `/.well-known/jwks.json`. [api/oidc.py:100-152]
- [ ] **O.3** Aggiungere `@limiter.limit("120/minute")` a `/oauth2/userinfo`. [api/oidc.py:155-201]
- [ ] **O.4** Aggiungere `@limiter.limit("30/minute")` a `/oauth2/logout` (GET e POST). [api/oidc.py:204-308]
- [ ] **O.5** Aggiungere test in `tests/integration/test_rate_limit.py` per ogni endpoint.

## Workstream P — DCR Hardening 🟡

DCR accetta `token_endpoint_auth_method=none` anche per client che dovrebbero essere confidential.

- [ ] **P.1** In `api/oidc.py:register_oauth_client`, rifiutare `token_endpoint_auth_method=none` se `grant_types` contiene `"authorization_code"` con `client_secret_*` o se il client vuole risorse protette server-side. [api/oidc.py:354-449]
- [ ] **P.2** Validare `client_uri`, `logo_uri`, `tos_uri`, `policy_uri` come HTTPS-only (eccetto loopback). [api/oidc.py:334-351]
- [ ] **P.3** Validare formato `software_statement` (JWT) se presente. [api/oidc.py:331]
- [ ] **P.4** Aggiungere test in `tests/integration/test_dcr_validation.py`:
  - `token_endpoint_auth_method=none` + confidential grant → 400
  - `client_uri=http://evil.com` → 400
  - `software_statement` non-JWT → 400

## Workstream Q — State Parameter Validation 🟡

Il parametro `state` non è validato in modo robusto. Un attacker può predire/iniettare state.

- [ ] **Q.1** In `authorize_post`, loggare warning se `state` è assente (best practice, non MUST). [api/auth.py:234-441]
- [ ] **Q.2** Aggiungere `state` al modello `AuthorizationCode` per binding server-side (opzionale, NON richiesto da spec).
- [ ] **Q.3** Aggiungere test in `tests/integration/test_state_param.py`:
  - Auth request senza state + redirect senza state → warning loggato
  - Auth request con state + redirect con state matching → 200
  - Auth request con state + redirect con state MISMATCH → errore

## Workstream R — JWKS Status Disclosure 🟡

Le chiavi revoked sono nascoste dal JWKS, ma se un client conserva un vecchio `kid` non ha modo di sapere se è stato revocato.

- [ ] **R.1** Creare `GET /oauth2/jwks/status` che ritorna keyring completo con `status` per ogni `kid`. [api/oidc.py:100-152]
- [ ] **R.2** Proteggere l'endpoint con rate limit e (opzionalmente) autenticazione admin.
- [ ] **R.3** Aggiungere test in `tests/integration/test_jwks_status.py`:
  - Chiave attiva → status=active
  - Chiave verifying → status=verifying
  - Chiave revocata → status=revoked

## Workstream S — Device Authorization Grant (RFC 8628) 🟡

Non implementato. Necessario per client IoT / CLI headless.

- [ ] **S.1** Creare `services/device_code.py` con modello `DeviceCode` (device_code, user_code, client_id, scope, expires_at, interval, last_poll_at).
- [ ] **S.2** Implementare `POST /oauth2/device` (RFC 8628 §3.1) — emette device_code + user_code + verification_uri + interval.
- [ ] **S.3** Implementare `POST /oauth2/device/token` (RFC 8628 §3.4) — polling endpoint.
- [ ] **S.4** Creare UI `/device` per user_code entry e approvazione.
- [ ] **S.5** Aggiungere `device_authorization_endpoint` e `grant_types_supported += ["urn:ietf:params:oauth:grant-type:device_code"]` al discovery.
- [ ] **S.6** Aggiungere test in `tests/integration/test_device_flow.py`:
  - POST /oauth2/device → 200 con device_code + user_code
  - Poll senza user approval → `authorization_pending`
  - Poll dopo approval → access token
  - Poll slow_down → interval increase
  - Poll access_denied → 400

## Workstream T — OAuth 2.1 / FAPI Alignment 🟢 (nice-to-have)

Cleanup e rimozione pattern deprecati.

- [ ] **T.1** Rimuovere `Resource Owner Password Credentials` flow da `api/auth.py` o documentarlo esplicitamente come first-party-only.
- [ ] **T.2** Aggiungere supporto `client_secret_jwt` e `private_key_jwt` per `token_endpoint_auth_method` (opzionale FAPI).
- [ ] **T.3** Considerare `sender-constrained` tokens (DPoP, RFC 9449) per FAPI 2.0.
- [ ] **T.4** Documentare le differenze rispetto a FAPI 2.0 in `docs/FAPI.md`.

## Workstream U — Migrazione e Audit 🟢

Script di migrazione e logging per i cambiamenti breaking.

- [ ] **U.1** Creare `scripts/migrate_conformance_v1.py` che applica tutte le migration in sequenza.
- [ ] **U.2** Audit log di tutti i client modificati (PKCE enforcement, implicit grant removal, allowed_post_logout_redirect_uris).
- [ ] **U.3** Aggiornare `SECURITY.md` con la lista dei fix di conformance.
- [ ] **U.4** Aggiornare `FEATURES.md` con i nuovi claim OIDC (`amr`, `acr`, `sid`, `at_hash`).
- [ ] **U.5** Pubblicare una `CHANGELOG.md` con breaking changes: rimozione implicit, PKCE obbligatorio, logout redirect validation.

---

## Riepilogo Priorità

| Priorità | Count | Workstream |
|---|---|---|
| 🔴 P0 | 4 (split in 23 task) | A, B, D, E |
| 🟠 P1 | 7 (split in 47 task) | B, C, D, E, F, G, H, I, J |
| 🟡 P2 | 9 (split in 35 task) | K, L, M, N, O, P, Q, R, S |
| 🟢 Extra | 2 (split in 9 task) | T, U |
| **Totale** | **~114 task** | |

## Dipendenze tra Workstream

- **A (audience validation)** blocca **F (amr/acr)**, **K (DCR mgmt)**, **L (logout)**, **M (at_hash)**.
- **B (PKCE enforcement)** può procedere in parallelo.
- **C (CSRF)** richiede `services/csrf.py` integrazione.
- **D (logout redirect)** è indipendente.
- **E (implicit removal)** è indipendente.
- **F (amr/acr)** richiede **A** completato.
- **G (prompt)**, **H (max_age)**, **I (id_token_hint)** possono procedere in parallelo.
- **J (blacklist)** richiede `core/token_blacklist.py` refactor.
- **K, L, M, N, O, P, Q, R, S, T** sono migliorativi e possono essere schedulati dopo i P0/P1.

## Effort Stimato

| Fase | Effort | Note |
|---|---|---|
| **P0 (A, B-parte, D, E)** | 3-5 giorni | Security-critical, test esistenti da aggiornare. |
| **P1 completo** | 2-3 sprint | Richiede refactor di `services/jwt.py`, `api/auth.py`, `services/oidc.py`, `services/login_history.py`. |
| **P2 completo** | 3-4 sprint | RFC 7592, 8628, logout, hardening, discovery. |
| **T + U** | 1-2 giorni | Documentazione + migration script. |
| **Totale stimato** | **6-8 sprint** | Per un singolo dev con review continue. |

## Note Finali

- Ogni task checkbox deve essere accompagnato da un commit atomico con prefisso `OAUTH:` o `OIDC:` per tracciabilità.
- Dopo ogni Workstream completato, lanciare il test plan in [`docs/CONFORMANCE_TEST_PLAN.md`](CONFORMANCE_TEST_PLAN.md).
- L'ordine consigliato è A → E → D → B → C → F → G → H → I → J → K → L → M → N → O → P → Q → R → S → T → U.
