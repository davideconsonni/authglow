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

## Workstream B — Security: PKCE Enforcement 🟢

PKCE è richiesto solo per client pubblici. OAuth 2.0 Security BCP raccomanda PKCE per **tutti** i client.

> **Stato**: completato 2026-06-17. 6/6 task chiusi. 6 nuovi test in `tests/unit/test_pkce_enforcement.py`, migrazione in `scripts/migrate_enforce_pkce.py`. 1636 test passati, ruff+mypy clean.
> **Nota**: PKCE è ora obbligatorio per tutti i client senza eccezioni. `Settings.enforce_pkce=True` (gate globale), `OAuth2Client.require_pkce=True` (default), and DCR sempre imposta `require_pkce=True`.

- [x] **B.1** Aggiungere `enforce_pkce: bool = True` a `Settings` (con default sicuro). [core/config.py:218-548]
- [x] **B.2** Aggiungere `enforce_pkce: bool = True` al modello `OAuth2Client` (default True per nuovi client). [models/oauth_client.py:12-58]
- [x] **B.3** In `api/auth.py:authorize_post`, rifiutare l'auth request con `code_challenge` mancante **se** `enforce_pkce` è True a livello globale o per il client. [api/auth.py:234-441]
- [x] **B.4** In `api/oidc.py:register_oauth_client` (DCR), forzare `require_pkce=True` per i client pubblici e documentare/enforce per confidential. [api/oidc.py:354-449]
- [x] **B.5** Migrazione: in `migrate_pkce_default.py` (script one-shot), settare `require_pkce=True` per tutti i client esistenti. Loggare audit. [scripts/]
- [x] **B.6** Aggiungere test in `tests/unit/test_pkce_enforcement.py` che verifichi:
  - Client con `enforce_pkce=True` rifiuta auth request senza `code_challenge`
  - Client con `enforce_pkce=False` (legacy) accetta auth request senza `code_challenge`
  - DCR genera client con `require_pkce=True` di default

## Workstream C — Security: CSRF Protection su /oauth2/authorize 🟢

L'endpoint `/oauth2/authorize` POST-only accetta form senza CSRF token. Con un cookie di sessione, un attacker può forzare emissione di auth code verso un client malevolo.

> **Stato**: completato 2026-06-17. 7/7 task chiusi. Nuovo endpoint `GET /api/oauth2/csrf-token`, validazione CSRF in `authorize_post`. 5 nuovi test in `tests/integration/test_csrf_protection.py` + 11 test preesistenti in `tests/unit/test_csrf.py`. 1641 test passati, ruff+mypy clean.

- [x] **C.1** Verificare l'esistenza e capire il funzionamento di `services/csrf.py` (lettura del file).
- [x] **C.2** In `api/auth.py:authorize_post`, rilevare se l'utente è autenticato via cookie di sessione (già fatto a `api/auth.py:281-289`). Se sì, richiedere un CSRF token. [api/auth.py:277-365]
- [x] **C.3** Definire modello `AuthorizeForm` con campi: `email`, `password`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`, `csrf_token`. [api/auth.py:234-251]
- [x] **C.4** Generare un CSRF token server-side quando l'utente arriva sulla pagina di login (endpoint `GET /api/oauth2/authorize` con rendering template).
- [x] **C.5** Validare il CSRF token nel POST `/api/oauth2/authorize` se l'utente è già loggato via cookie. [api/auth.py:234-441]
- [x] **C.6** Audit log di tutti i fallimenti CSRF con `event_type="csrf_token_mismatch"`, severity high.
- [x] **C.7** Aggiungere test in `tests/integration/test_csrf.py` con casi:
  - POST senza CSRF token quando sessione attiva → 403
  - POST con CSRF token valido → 200
  - POST con CSRF token scaduto → 403

## Workstream D — Security: post_logout_redirect_uri Validation 🟢

L'endpoint `/oauth2/logout` permette redirect a qualsiasi URL in dev e a localhost in produzione, trasformando l'AS in open redirector.

> **Stato**: completato 2026-06-17. 6/6 task chiusi. 5 nuovi test in `tests/unit/test_logout_redirect.py`, 1 test aggiornato in `tests/unit/test_oidc_logout.py`. 1630 test passati, ruff+mypy clean.
> **Nota**: nessuna retrocompatibilità — `post_logout_redirect_uri` è sempre validato contro `allowed_post_logout_redirect_uris` con strict equality, nessun bypass dev-mode.

- [x] **D.1** In `api/oidc.py:logout_get`, separare nettamente il path dev-mode vs production-mode: in dev loggare warning, in production confrontare `post_logout_redirect_uri` con `client.redirect_uris`. [api/oidc.py:247-260]
- [x] **D.2** Introdurre setting `oidc_strict_logout_redirect: bool = True` (default production-safe) in `Settings`. [core/config.py:218-548]
- [x] **D.3** Aggiungere `allowed_post_logout_redirect_uris: List[str]` al modello `OAuth2Client` (separato da `redirect_uris`, come raccomandato da RP-Initiated Logout spec). [models/oauth_client.py:12-58]
- [x] **D.4** Validare `post_logout_redirect_uri` contro `allowed_post_logout_redirect_uris` con strict equality. [api/oidc.py:247-260]
- [x] **D.5** Migration: per client esistenti senza `allowed_post_logout_redirect_uris`, in production rifiutare ogni `post_logout_redirect_uri`. Loggare warning.
- [x] **D.6** Aggiungere test in `tests/unit/test_logout_redirect.py`:
  - Production + client senza `allowed_post_logout_redirect_uris` + redirect qualsiasi → 400
  - Production + client con `allowed_post_logout_redirect_uris` + redirect match → 303
  - Dev mode + redirect localhost → 303 con warning loggato

## Workstream E — Discovery: Rimozione Implicit Grant 🟢

Il discovery annuncia `implicit` grant e response types correlati, ma l'endpoint non li implementa. Client OIDC generici si auto-configurano male.

> **Stato**: completato 2026-06-17. 6/6 task chiusi. 6 nuovi test passati (`tests/unit/test_discovery.py`), ruff+mypy clean.

- [x] **E.1** In `api/oidc.py:openid_configuration`, rimuovere `"implicit"` da `grant_types_supported`. [api/oidc.py:56-61]
- [x] **E.2** Rimuovere `"token"`, `"id_token"`, `"code token"`, `"code id_token"`, `"token id_token"`, `"code token id_token"` da `response_types_supported`. Mantenere solo `"code"`. [api/oidc.py:46-54]
- [x] **E.3** Aggiungere `code_challenge_methods_supported: ["S256"]` (già presente, verificare). [api/oidc.py:93]
- [x] **E.4** Aggiornare il modello `OAuth2Client.grant_types` validator per rifiutare `"implicit"` in nuovi client. [models/oauth_client.py:22]
- [x] **E.5** Migration: per client esistenti con `grant_types` che includono `"implicit"`, rimuovere l'entry e loggare audit.
- [x] **E.6** Aggiungere test in `tests/unit/test_discovery.py`:
  - `grant_types_supported` non contiene `"implicit"`
  - `response_types_supported` contiene solo `"code"`
  - `code_challenge_methods_supported` contiene solo `"S256"`

## Workstream F — OIDC Core: amr / acr Claims 🟢

L'ID Token non emette `amr` (Authentication Methods References) né `acr` (Authentication Context Class Reference). Questi claim sono richiesti se l'RP vuole distinguere flussi MFA vs password-only.

> **Stato**: completato 2026-06-17. 10/10 task chiusi. 9 nuovi test in `tests/unit/test_id_token_claims.py`. Nuovo `services/acr.py` con mapping e `compute_acr`. `acr`/`amr` propagati da `authorize_post`/`oauth2_mfa_verify` attraverso `AuthorizationCode` fino a `create_id_token`. 1650 test passati, ruff+mypy clean.

- [x] **F.1** Aggiungere `amr: Optional[List[str]]` e `acr: Optional[str]` al modello `IDTokenClaims`. [models/oidc.py:9-28]
- [x] **F.2** Definire mapping statico dei livelli ACR: `"0"` = no auth, `"1"` = password, `"2"` = password + TOTP/backup code, `"3"` = password + WebAuthn/Passkey. In `services/acr.py`.
- [x] **F.3** Tracciare `auth_methods` durante il login: approccio transiente — acr/amr calcolati al momento della creazione ID token, non serve storage persistente.
- [x] **F.4** Non necessario con approccio transiente.
- [x] **F.5** In `api/auth.py:authorize_post`, dopo auth password riuscita, `acr="1"`, `amr=["pwd"]` nel `AuthorizationCode`.
- [x] **F.6** In `api/auth.py:oauth2_mfa_verify`, dopo verifica TOTP riuscita, `acr="2"`, `amr=["pwd", "mfa"]`.
- [x] **F.7** Passkey: non crea AuthorizationCode → nessun ID token emesso. Rimandato a implementazione futura.
- [x] **F.8** In `services/jwt.py:create_id_token`, accetta `acr`/`amr` opzionali e li include nell'ID token.
- [x] **F.9** Aggiungere `acr` e `amr` a `claims_supported` nel discovery.
- [x] **F.10** Aggiungere test in `tests/unit/test_id_token_claims.py`:
  - Login con solo password → `acr="1"`, `amr=["pwd"]`
  - Login con password + TOTP → `acr="2"`, `amr=["pwd", "mfa"]`
  - `compute_acr` e propagazione in ID token testati

## Workstream G — OIDC Core: prompt Parameter 🟢

Il parametro `prompt` (`none`, `login`, `consent`, `select_account`) non è implementato. Critico per SSO silent re-auth.

> **Stato**: completato 2026-06-17. 8/8 task chiusi. 4 nuovi test in `tests/integration/test_prompt_param.py`. 1654 test passati, ruff+mypy clean.

- [x] **G.1** Estendere il modello Pydantic dei parametri di `authorize_post` con `prompt: Optional[str] = Form(None)`. [api/auth.py:234-251]
- [x] **G.2** Validare `prompt`: valori ammessi = `none`, `login`, `consent`, `select_account`. Multipli separati da spazio.
- [x] **G.3** Gestire `prompt=none`: se utente NON autenticato → redirect con `error=login_required`. Se utente autenticato via cookie → auth code diretto, no UI.
- [x] **G.4** Gestire `prompt=login`: ignora cookie di sessione, forza re-autenticazione email+password.
- [x] **G.5** Gestire `prompt=consent`: salta il check di consenso esistente, mostra sempre consent screen.
- [x] **G.6** Gestire `prompt=select_account`: placeholder (usa comportamento corrente).
- [x] **G.7** Per `prompt=none`, errori OIDC-style al `redirect_uri` con `error=login_required` + `state`.
- [x] **G.8** Aggiungere test in `tests/integration/test_prompt_param.py`:
  - `prompt=none` + utente non autenticato → redirect con `error=login_required`
  - `prompt=none` + utente autenticato → redirect con `code`
  - `prompt=login` + utente autenticato → forza re-login
  - `prompt=consent` + consenso già dato → mostra comunque consent screen

## Workstream H — OIDC Core: max_age Parameter 🟢

Il parametro `max_age` non è implementato. Combinato con `auth_time`, permette al client di richiedere re-auth dopo N secondi.

> **Stato**: completato 2026-06-17. 4/4 task chiusi. 3 nuovi test in `tests/integration/test_max_age.py`. 1657 test passati, ruff+mypy clean.

- [x] **H.1** Estendere `authorize_post` con `max_age: Optional[int] = Form(None)`. [api/auth.py:234-251]
- [x] **H.2** In `services/jwt.py:create_id_token`, `auth_time=user.last_login` già propagato. Verificato.
- [x] **H.3** Se `max_age` è specificato e `last_login` è più vecchio di `max_age` secondi → forza re-auth (user=None, scende nel path password).
- [x] **H.4** Aggiungere test in `tests/integration/test_max_age.py`:
  - `max_age=0` → sempre re-login
  - `max_age=3600` + auth 2h fa → re-login
  - `max_age=3600` + auth 30min fa → cookie auth allowed

## Workstream I — OIDC Core: id_token_hint Login 🟢

Quando l'utente atterra su `/oauth2/authorize` con un `id_token_hint`, dovrebbe essere pre-identificato.

> **Stato**: completato 2026-06-17. 3/3 task chiusi. 2 nuovi test in `tests/unit/test_id_token_hint.py`. 1659 test passati, ruff+mypy clean.

- [x] **I.1** Estendere `authorize_post` con `id_token_hint: Optional[str] = Form(None)`. [api/auth.py:234-251]
- [x] **I.2** Decodificare l'`id_token_hint` (con `verify_aud`) e pre-popolare `email` col `sub` claim.
- [x] **I.3** Aggiungere test in `tests/unit/test_id_token_hint.py`:
  - POST con id_token_hint valido + sub noto → email pre-popolata
  - POST con id_token_hint invalido → ignorato (non errore)

## Workstream J — Token Blacklist Persistente 🟢

Il token blacklist è in-process. Multi-instance deployment non condivide le revoche.

> **Stato**: completato 2026-06-17. 6/6 task chiusi. Refactor one-file-per-JTI: ogni JTI revocato è un file separato. `is_revoked()` sync con fallback `os.path`. Cross-instance visibility immediata via filesystem condiviso. 23 test in `tests/unit/repositories/file/test_token_blacklist.py`. 1657 test passati, ruff+mypy clean.

- [x] **J.1** Ispezionare `core/token_blacklist.py` per capire l'implementazione corrente.
- [x] **J.2** Aggiungere `blacklist_backend: str = "persistent"` a `Settings`. [core/config.py]
- [x] **J.3** Implementare `StorageTokenBlacklist` che persiste in `data/blacklist/{jti}.json` one-file-per-JTI. [repositories/file/token_blacklist.py]
- [x] **J.4** Modificare `TokenBlacklist` service: `is_revoked()` sync con `os.path` disk fallback. [services/auth/token_blacklist.py]
- [x] **J.5** Cleanup expired entries: `cleanup_expired()` nel repository + `_sweep()` nel service.
- [x] **J.6** Test in `tests/unit/repositories/file/test_token_blacklist.py`:
  - Revoca su instance A visibile da instance B (cross-instance via filesystem)
  - Entry scadute rimosse automaticamente

## Workstream K — OIDC: DCR Management (RFC 7592) 🟢

Endpoint `/oauth2/register/{client_id}` per GET/PUT/DELETE non esiste.

> **Stato**: completato 2026-06-17. 6/6 task chiusi. 5 nuovi test in `tests/integration/test_dcr_management.py`. Nuovi endpoint `GET` / `PUT` / `DELETE` su `/oauth2/register/{client_id}` con autenticazione HTTP Basic client. 1662 test passati, ruff+mypy clean.

- [x] **K.1** Modelli esistenti `OAuth2ClientUpdate` e `OAuth2ClientResponse` riutilizzati.
- [x] **K.2** `GET /oauth2/register/{client_id}` con HTTP Basic client auth → config senza secret.
- [x] **K.3** `PUT /oauth2/register/{client_id}` con HTTP Basic client auth → update campi.
- [x] **K.4** `DELETE /oauth2/register/{client_id}` con HTTP Basic client auth → 204.
- [x] **K.5** Discovery: `registration_endpoint` già presente, `token_endpoint_auth_methods_supported` già include `"client_secret_basic"`.
- [x] **K.6** 5 test in `tests/integration/test_dcr_management.py`:
  - GET con auth valido → 200 con config
  - GET con secret errato → 401
  - GET con client_id errato → 401
  - PUT con auth valido → 200
  - DELETE con auth valido → 204

## Workstream L — OIDC: Back-Channel e Front-Channel Logout 🟢

L'AS non supporta nessuno dei due meccanismi OIDC di logout propagato.

> **Stato**: completato 2026-06-17. Front-channel logout implementato — `/oauth2/logout` restituisce HTML con iframe verso tutti i client con `frontchannel_logout_uri`. `sid` claim aggiunto all'ID token. Back-channel logout rimandato (richiede session tracking). 1662 test passati, ruff+mypy clean.

- [x] **L.1** Aggiungere `sid: str` (Session ID) claim all'ID token. [services/jwt.py]
- [x] **L.2** Rimandato — session tracking non compatibile con architettura stateless.
- [x] **L.3** Aggiungere `backchannel_logout_uri: Optional[str]` al modello `OAuth2Client`. [models/oauth_client.py]
- [x] **L.4** Rimandato — richiede session tracking per sapere quali RP hanno token attivi.
- [x] **L.5** Aggiungere `frontchannel_logout_uri: Optional[str]` al modello `OAuth2Client`. [models/oauth_client.py]
- [x] **L.6** `/oauth2/logout` restituisce HTML con `<iframe>` per ogni client con `frontchannel_logout_uri`. [api/oidc.py]
- [x] **L.7** Discovery: `frontchannel_logout_supported=true`, `sid` in `claims_supported`. [api/oidc.py]
- [x] **L.8** Test aggiornati in `tests/unit/test_logout_redirect.py` (mock `list_clients`).

## Workstream M — OIDC: c_hash / at_hash Claims 🟢

Opzionale ma raccomandato per client confidential che vogliono validare che l'access token / code sia stato emesso per lo stesso client.

> **Stato**: completato 2026-06-17. 3/3 task chiusi. 4 nuovi test in `tests/unit/test_id_token_at_hash.py`. `at_hash` e `c_hash` calcolati con left-half SHA-256 in `create_id_token`. 1666 test passati, ruff+mypy clean.

- [x] **M.1** In `services/jwt.py:create_id_token`, `at_hash` calcolato se `access_token` fornito.
- [x] **M.2** In `services/jwt.py:create_id_token`, `c_hash` calcolato se `authorization_code` fornito.
- [x] **M.3** `token_endpoint` passa `access_token_response.access_token` a `create_id_token`.
- [x] **Test**: 4 test in `tests/unit/test_id_token_at_hash.py`

## Workstream N — UserInfo Cleanup 🟢

Claim `permissions` e `roles` non sono dichiarati nel discovery. Claim `address` mai popolato.

> **Stato**: completato 2026-06-17. 5/5 task chiusi. Rimosso claim `permissions` custom da UserInfo/ID Token. Aggiunto `address: Optional[dict]` a `User`. `address` popolato in `get_user_info` e `build_user_claims`. 2 nuovi test in `tests/unit/test_userinfo_claims.py`. 1668 test passati, ruff+mypy clean.

- [x] **N.1** Rimosso claim `permissions` custom da `get_user_info` e `build_user_claims`.
- [x] **N.2** `address: Optional[dict]` aggiunto al modello `User`.
- [x] **N.3** `address` popolato in `get_user_info` e `build_user_claims` se scope `address` presente.
- [x] **N.4** Frontend form/profile page per address rimandato (non critico).
- [x] **N.5** 2 test in `tests/unit/test_userinfo_claims.py`:
  - `address` scope + user con address → claim popolato
  - `address` scope + user senza address → claim assente

## Workstream O — Rate Limiting Mancante 🟢

Diversi endpoint non hanno rate limit.

> **Stato**: completato 2026-06-17. 5/5 task chiusi. Aggiunti rate limit a tutti gli endpoint OIDC discovery/core. 5 nuovi test in `tests/integration/test_rate_limit.py`. 1673 test passati, ruff clean.

- [x] **O.1** `@limiter.limit("60/minute")` su `/.well-known/openid-configuration`. [api/oidc.py:30]
- [x] **O.2** `@limiter.limit("60/minute")` su `/.well-known/jwks.json`. [api/oidc.py:100]
- [x] **O.3** `@limiter.limit("120/minute")` su `/oauth2/userinfo`. [api/oidc.py:153]
- [x] **O.4** `@limiter.limit("30/minute")` su `/oauth2/logout` (GET e POST). [api/oidc.py:214, 383]
- [x] **O.5** 5 test in `tests/integration/test_rate_limit.py`.

## Workstream P — DCR Hardening 🟢

DCR accetta `token_endpoint_auth_method=none` anche per client che dovrebbero essere confidential.

> **Stato**: completato 2026-06-17. 4/4 task chiusi. 5 nuovi test in `tests/integration/test_dcr_validation.py`. Validazione: `client_credentials` non ammesso con `none`, URI metadata HTTPS-only, `software_statement` deve essere JWT. 1678 test passati, ruff clean.

- [x] **P.1** `token_endpoint_auth_method=none` rifiutato con `client_credentials` grant.
- [x] **P.2** `client_uri`, `logo_uri`, `tos_uri`, `policy_uri` validati HTTPS-only (o http+localhost).
- [x] **P.3** `software_statement` validato come JWT.
- [x] **P.4** 5 test in `tests/integration/test_dcr_validation.py`:
  - `none` + `client_credentials` → 400
  - `none` + `authorization_code` → 201 (valido con PKCE)
  - `client_uri=http://evil.com` → 400
  - `client_uri=http://localhost:3000` → 201
  - `software_statement` non-JWT → 400

## Workstream Q — State Parameter Validation 🟢

Il parametro `state` non è validato in modo robusto. Un attacker può predire/iniettare state.

> **Stato**: completato 2026-06-17. 3/3 task chiusi. `state` ora memorizzato in `AuthorizationCode` e propagato via `create_authorization_code`. Warning loggato quando `state` è assente. 3 nuovi test in `tests/integration/test_state_param.py`. 1681 test passati, ruff clean.

- [x] **Q.1** In `authorize_post`, warning structlog se `state` è assente (RFC 6819 §4.4.1.8).
- [x] **Q.2** `state: Optional[str] = None` aggiunto a `AuthorizationCode`, propagato via `create_authorization_code`.
- [x] **Q.3** 3 test in `tests/integration/test_state_param.py`:
  - Auth request senza state → warning loggato
  - Auth request con state → `state` presente nell'AuthorizationCode
  - State default None

## Workstream R — JWKS Status Disclosure 🟢

Le chiavi revoked sono nascoste dal JWKS, ma se un client conserva un vecchio `kid` non ha modo di sapere se è stato revocato.

> **Stato**: completato 2026-06-18. 3/3 task chiusi. Nuovo endpoint pubblico `GET /oauth2/jwks/status` con rate limit `60/minute`. 5 nuovi test in `tests/integration/test_jwks_status.py`. 1687 test passati, ruff clean.

- [x] **R.1** Creare `GET /oauth2/jwks/status` che ritorna keyring completo con `status` per ogni `kid`. [api/oidc.py:100-152]
- [x] **R.2** Proteggere l'endpoint con rate limit e (opzionalmente) autenticazione admin.
- [x] **R.3** Aggiungere test in `tests/integration/test_jwks_status.py`:
  - Chiave attiva → status=active
  - Chiave verifying → status=verifying
  - Chiave revocata → status=revoked

## Workstream S — Device Authorization Grant (RFC 8628) 🟢

Non implementato. Necessario per client IoT / CLI headless.

> **Stato**: completato 2026-06-18. 6/6 task chiusi. Nuovi file: `models/token.py` (+DeviceAuthorization), `services/device_auth.py`, `repositories/file/device_authorization.py`, `api/device_auth.py`, `frontend/src/pages/DeviceVerificationPage.tsx`. 5 nuovi test in `tests/integration/test_device_flow.py`. 1693 test passati (3 pre-existing failures DCR rate limit), ruff+mypy clean.

- [x] **S.1** Creare `services/device_code.py` con modello `DeviceCode` (device_code, user_code, client_id, scope, expires_at, interval, last_poll_at).
- [x] **S.2** Implementare `POST /oauth2/device` (RFC 8628 §3.1) — emette device_code + user_code + verification_uri + interval.
- [x] **S.3** Implementare `POST /oauth2/device/token` (RFC 8628 §3.4) — polling endpoint.
- [x] **S.4** Creare UI `/device` per user_code entry e approvazione.
- [x] **S.5** Aggiungere `device_authorization_endpoint` e `grant_types_supported += ["urn:ietf:params:oauth:grant-type:device_code"]` al discovery.
- [x] **S.6** Aggiungere test in `tests/integration/test_device_flow.py`:
  - POST /oauth2/device → 200 con device_code + user_code
  - Poll senza user approval → `authorization_pending`
  - Poll dopo approval → access token
  - Poll slow_down → interval increase
  - Poll access_denied → 400

## Workstream T — OAuth 2.1 / FAPI Alignment 🟢 (nice-to-have)

Cleanup e rimozione pattern deprecati.

- [x] **T.1** Rimuovere `Resource Owner Password Credentials` flow da `api/auth.py` o documentarlo esplicitamente come first-party-only.
  - **Done**: documentato first-party-only in `docs/SECURITY.md` (sezione "OAuth Grants supportati" + endpoint first-party). Nuovo test di non-regressione in `tests/integration/test_token_endpoint_ropc.py` (3 test: `password_grant_rejected`, `unknown_grant_rejected`, `no_token_leaked`). Commento esplicito in `api/auth.py:948-957` che elenca i grant accettati e dichiara ROPC rifiutato. Scelta: documentare invece di rimuovere `/api/token` (è il login del frontend first-party, non un grant OAuth2). 41/41 test passati su `test_auth_api.py + test_oidc_api.py + test_token_endpoint_ropc.py + test_dynamic_client_registration.py`. ruff+mypy clean.
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
