# AuthGlow — Piano di Production Readiness (2026-09-03)

> **Obiettivo**: rispondere a una domanda sola — *cosa mi impedisce oggi
> di portare AuthGlow in produzione come IdP enterprise-grade?* —
> con una checklist azionabile, una voce alla volta.
> **Metodo**: non ho ricopiato `docs/plans/VAPT_FIX_PLAN.md` (126
> finding, 63 ancora aperti secondo il documento). Ho **riverificato nel
> codice attuale** ogni voce che finisce in Tier 0/1 qui sotto — diverse
> voci segnate `[ ]` nel VAPT plan risultano **già risolte** (vedi
> sezione "Falsi allarmi" in fondo, da chiudere nel plan originale).
> Include anche i 4 finding OAuth2/OIDC-specifici emersi dall'audit di
> conformità di ieri (`OAUTH2_OIDC_COMPLIANCE_PLAN.md`).
> **Convenzione ID**: riuso gli ID `VAPT-NNN` dove la voce esiste già
> nel plan originale (per tracciabilità); i finding nuovi di questa
> sessione usano `OIDC-NNN`.

## Come leggere questo documento

Tre livelli, non di severità astratta ma di **urgenza reale per
andare live**:

- **Tier 0 — blocca il go-live.** Non ci metterei un IdP enterprise in
  produzione con questi aperti. Sono pochi (6) e quasi tutti piccoli da
  chiudere.
- **Tier 1 — prima sprint post-launch.** Reali, ma non impediscono di
  aprire i rubinetti se hai un piano concreto per chiuderli entro
  poche settimane.
- **Tier 2 — backlog di hardening.** Buone pratiche, supply chain,
  validazione input. Nessuna best-practice violata qui ti espone a un
  incidente il giorno 1.

Spunta `[x]` quando risolto. Nessuna dipendenza tra le voci di uno
stesso tier — falle nell'ordine che preferisci.

---

## TIER 0 — Blocca il go-live (6 voci)

### T0-1 — [x] CSRF costruito ma non collegato a nessun endpoint (VAPT-066)

- **Verificato oggi**: `grep -rn "require_csrf" api/*.py` → zero
  risultati. `cors_allow_credentials: bool = True` di default
  (`core/config.py:300`).
- **Perché blocca**: con cookie di sessione + CORS credentialed,
  un sito terzo può forzare azioni di stato (cambio password,
  revoca consensi, creazione API key) per conto di un utente loggato,
  senza che serva rubare nulla — solo far cliccare un link.
- **Fix**: collegare `CSRFTokenService` (`services/csrf.py`) — impostare
  il cookie `csrf_session_id` al login, aggiungere
  `Depends(require_csrf)` sulle route che mutano stato
  (`/oauth2/consent`, `/api/users/*`, `/api/keys/*`,
  `/api/profile/me/change-password`, `/api/profile/me/delete`). In
  alternativa dichiarata: passare a un modello puro bearer-token (niente
  cookie per le chiamate API) e documentarlo esplicitamente — ma oggi
  il sistema usa cookie httpOnly per il flow first-party, quindi questa
  alternativa richiede più lavoro della prima.
- **Risolto (2026-09-03)** — con **correzione della premessa e un bug
  funzionale trovato e sistemato**:
  - **Premessa stantia**: l'enforcement CSRF esisteva già, ma NON via
    `Depends(require_csrf)` (ecco perché il grep del piano trovava
    zero) — c'era un middleware globale (`middleware/csrf.py`,
    montato in `main.py:192`), l'endpoint di emissione
    (`/api/oauth2/csrf-token`) e il frontend che invia già
    `X-CSRF-Token` su ogni richiesta unsafe (`api.ts:120-122`).
  - **Bug G0 (funzionale, confermato con probe empirica)**: doppio
    enforcement — il middleware consumava il token one-time
    dell'header, poi il check inline dentro `authorize_post` richiedeva
    un token nel form: con semantiche replace+consume NESSUNA
    combinazione poteva passare → **authorize da utente loggato sempre
    403** in produzione (i test non lo beccavano: app bare senza
    middleware).
  - **Fix applicati**: `validate_token` non consumante (il token resta
    valido per il TTL di 30 min, legato al cookie httpOnly del
    possessore); check inline rimosso da `authorize_post` (il
    middleware è l'unico punto di enforcement; i check
    `is_active`/`suspended` restano); gate del middleware esteso a
    cookie refresh **e** `csrf_session_id` (login CSRF coperto) con
    bypass per credenziali esplicite (`Authorization`/`X-API-Key`,
    CSRF-immuni per costruzione); audit `csrf_token_mismatch`
    (severity warning, path/origin/request_id) nel middleware;
    frontend: cache del token (1 fetch per page load, elimina la race
    su richieste unsafe parallele) + clear & retry-once su 403-CSRF.
  - **Verifica**: probe end-to-end sulla sequenza esatta della SPA —
    authorize via cookie ora **200** (prima 403), attacco cross-site
    senza header **403**. Test: 12 nuovi casi gate
    (`tests/integration/test_csrf_middleware.py`), service test
    non-consuming, test authorize rifatti con middleware montato,
    frontend +3 (cache/retry/403 non-CSRF). Suite completa 2596
    passed; eslint/tsc/ruff/mypy puliti.
  - **Follow-up opzionale**: e2e Playwright sul flusso authorize.

### T0-2 — [x] `enable_docs=True` di default, non legato all'ambiente (VAPT-070)

- **Verificato oggi**: `core/config.py:203` → `enable_docs: bool = True`
  incondizionato; `main.py:164-166` lo usa così com'è, nessun controllo
  su `app_env`.
- **Perché blocca**: `/docs`, `/redoc`, `/openapi.json` espongono
  l'intera superficie API — inclusi gli endpoint admin distruttivi — a
  chiunque, senza autenticazione, se l'operatore dimentica di settare
  la variabile d'ambiente.
- **Fix**: `enable_docs: bool = Field(default_factory=lambda: not
  is_production_env())` oppure, più semplice, forzare `False` quando
  `app_env == "production"` in un `model_validator`, sullo stesso
  pattern già usato per `debug` (`config.py:571`).
- **Risolto (2026-09-03)**: `model_validator(mode="before")`
  `_apply_enable_docs_production_default` in `core/config.py` — default
  `False` quando `app_env == "production"` (case-insensitive) e
  `ENABLE_DOCS` non impostato; il validator vede il dict mergiato
  env + `.env`, quindi copre anche i deploy configurati via file.
  Opt-in esplicito rispettato ma con `UserWarning` nel log di boot
  (la deroga resta visibile). Test:
  `TestEnableDocsProductionDefault` in `tests/unit/test_config.py`
  (5 casi) + `_env_file=None` nell'helper `_make_settings_with` per
  isolare i test dal `.env` locale dello sviluppatore (che qui
  impostava `ENABLE_DOCS=true` e inquinava i casi "non impostato").
  `ENABLE_DOCS` documentato in `backend/.env.example`.
  **Nota emersa a fattura chiusa**: il toggle admin "Enable API docs"
  (`api/admin_settings.py:67`, `restart_required=True`) è inefficace —
  gli override vengono applicati nel `lifespan` (`main.py:117-121`),
  dopo la costruzione di `FastAPI(...)` in cui `docs_url` è già deciso;
  da affrontare a parte se si vuole rendere funzionante o rimuoverlo.

### T0-3 — [x] `passkey_rp_id` / `passkey_origin` di default puntano a `localhost` (VAPT-069)

- **Verificato oggi**: `core/config.py:431,433` →
  `passkey_rp_id: str = "localhost"`,
  `passkey_origin: str = "http://localhost:8000"`.
- **Perché blocca**: se usi i passkey in produzione (la app li supporta
  in modo completo — enrollment, login, gestione dispositivi), WebAuthn
  richiede un match esatto RP ID ↔ origin del browser. Con i default,
  la cerimonia accetta silenziosamente richieste `http://localhost` da
  qualunque servizio locale sulla macchina del server, oppure fallisce
  in modo confuso se il dominio reale non combacia.
- **Fix**: default a stringa vuota + hard-fail all'avvio in produzione
  se non configurati esplicitamente, stesso pattern di
  `oauth2_client_secret`.
- **Nota**: se non usi passkey in produzione nel breve termine, questo
  scende a Tier 1 — ma verificalo prima di derubricarlo.
- **Risolto (2026-09-03)** — con **correzione del "perché blocca"**:
  riverificando è emerso che le cerimonie WebAuthn reali (register
  begin/complete, auth begin/complete in `api/passkey.py:37-61`)
  derivano `rp_id`/`origin` **dinamicamente dagli header** della
  request e non leggono questi setting; li consumano solo le route
  admin di listing/CRUD (`admin.py:74,1390`), dove restano inerti.
  Il rischio "cerimonia accetta richieste localhost" quindi non
  esiste oggi — restano però la config fuorviante (l'admin UI espone
  i due setting come se governassero le cerimonie) e la mine futura
  di un rewiring. Fix applicato: validator
  `_validate_passkey_defaults_for_production` (`core/config.py`) che
  fa **hard-fail al boot in produzione** se i due setting sono vuoti
  o localhost (hostname confrontato esatto, no substring → nessun
  falso positivo tipo `idp.localhostdomain.example.com`); default dev
  invariati. Test: `TestPasskeyDefaultsHardFailInProduction`
  (6 casi in `tests/unit/test_config.py`, helper `_make_settings_with`
  con default passkey non-localhost come già per oauth2) +
  allineato `test_cookie_auth.py:294`. Nota hard-fail aggiunta al
  blocco PASSKEY di `.env.example`.

### T0-4 — [x] Nessun exception handler globale + errori verbosi in risposta (VAPT-074 + VAPT-073)

- **Verificato oggi**: `grep -n "add_exception_handler" main.py` → zero
  risultati. Confermata inoltre almeno una `except Exception` che passa
  in modo silente (`api/auth.py`, invio email di benvenuto) — quella è
  innocua, ma altrove (`passkey.py:177,333`, `federation.py:93,159,242`,
  `admin.py:186,266,904`) `str(e)` finisce nella risposta HTTP.
- **Perché blocca**: senza handler globale, un'eccezione non prevista
  (I/O, storage, chiamata esterna) può restituire il traceback di
  default di FastAPI se `debug` viene mai acceso per errore, e anche
  con `debug=False` i punti sopra restituiscono comunque messaggi di
  libreria interni (path, dettagli WebAuthn, frammenti di risposte
  upstream IdP) — inaccettabile per un IdP che tratta dati di
  autenticazione.
- **Fix**: un `@app.exception_handler(Exception)` che logga via
  structlog con `request_id` di correlazione e risponde con un 500
  generico stabile; sostituire gli `str(e)` puntuali con log
  server-side + codice errore stabile in risposta.
- **Risolto (2026-09-03)**:
  - **Handler globale**: nuovo modulo `api/error_handlers.py` con
    `register_global_error_handler(app)` (stesso pattern di
    `register_oauth2_error_handler`), cablato in `main.py`. Audit
    `unhandled_exception` (severity error, path/method/error_class,
    `request_id` ereditato dai contextvars VAPT-131) + entry structlog
    con traceback + **500 generico stabile**
    `{"detail": "Internal server error"}`.
  - **5 siti leak genericizzati** (dettaglio stabile in response,
    `str(e)` solo server-side nell'audit, `raise ... from e`):
    `passkey.py` ×2 (interni libreria WebAuthn),
    `federation.py` ×3 (frammenti risposta IdP upstream, interni
    validazione JWT, login federato).
  - **Tenuti di proposito** (messaggi controllati, superficie
    admin/protocollo): `ClaimsEssentialMissingError` e `INVALID_SCOPE`
    (error_description RFC 6749 §5.2), validazioni admin settings /
    claim policy / webhooks, `ValueError` handler in admin, risultati
    bulk-op admin (info operativa per l'admin del sistema stesso).
  - Test: `tests/integration/test_global_error_handler.py` (500
    generico + audit); 2 test federation aggiornati — asserivano
    proprio il leak ("nonce"/"signature" nel body) e ora il contratto
    generico. Suite completa 2598 passed, ruff/mypy puliti.

### T0-5 — [x] Refresh token: 30 giorni hardcoded, la config viene ignorata (VAPT-058)

- **Verificato oggi**: `expires_in_days=30` letterale in
  `api/auth.py:1309`, `api/auth.py:1726`, `api/passkey.py:325` — la
  config `refresh_token_expire_days` (default 7) non viene mai letta
  in questi call site.
- **Perché blocca**: qualunque policy di sicurezza aziendale
  ("i refresh token scadono in N giorni") che l'operatore imposta via
  variabile d'ambiente **non ha alcun effetto**. Per un IdP venduto
  come enterprise, questo è esattamente il tipo di gap che un audit di
  un cliente trova per primo.
- **Fix**: sostituire i tre `30` con
  `self.settings.refresh_token_expire_days` (o equivalente iniettato).
  Un `grep -rn "expires_in_days=30"` deve tornare vuoto a fix
  applicato.
- **Risolto (2026-09-03)** — con **due scoperte oltre il piano**:
  - un **quarto call site** hardcoded non censito:
    `api/federation.py:356` (federation callback);
  - il **default del metodo** `create_refresh_token`
    (`services/refresh_token.py` → `expires_in_days: int = 30`) era
    anch'esso hardcoded, e la **rotazione**
    (`validate_and_rotate` non passa l'argomento) lo ereditava:
    ogni token ruotato viveva 30 giorni qualunque fosse la config.
  Fix: firma `expires_in_days: Optional[int] = None` con fallback su
  `Settings.refresh_token_expire_days` (sistema rotazione e caller
  futuri) + i 4 call site ora passano
  `settings.refresh_token_expire_days` (pattern già usato da
  `api/mfa.py:397` e `JWTService.create_refresh_token`,
  `services/jwt.py:405`). Test: default e token ruotato seguono la
  config (`TestVapt058ConfigDrivenExpiry`) + **guardia di regressione**
  source-scan che fallisce se un letterale `expires_in_days=30`
  rientra in `api/*.py` o nel service
  (`TestVapt058NoHardcodedExpiryLiteral`). Criterio di accettazione
  soddisfatto: `grep -rn "expires_in_days=30"` su `api/` → vuoto.

### T0-6 — [x] Nessun audit trail su disable MFA e su reuse-detection dei refresh token (VAPT-056 + VAPT-057)

- **Verificato oggi**: `api/mfa.py:154-177` (`disable_mfa`) — nessuna
  chiamata `audit_service`, nessuna `send_mfa_disabled_alert` (esiste
  in `security_notifications.py` ma non è mai invocata). Stesso per la
  revoca dell'intera famiglia di refresh token su reuse rilevato
  (`services/refresh_token.py:271-289`, `api/auth.py:529-559`).
- **Perché blocca**: sono i due eventi a più alto segnale di
  compromissione dell'intero sistema (qualcuno ha disattivato l'MFA di
  un account; qualcuno ha riusato un refresh token già consumato — il
  sintomo classico di un token rubato). Senza log, un SIEM/SOC
  enterprise non li vede mai. Per un prodotto che si propone come IdP
  aziendale, l'assenza di audit trail su questi due eventi è difficile
  da giustificare in una due diligence di sicurezza.
- **Fix**: aggiungere `audit_service.log_event(event_type="mfa_disabled", severity="warning", ...)` in `disable_mfa`, e
  `event_type="refresh_token_reuse_detected"` nel punto che chiama
  `_revoke_token_family`. Wireare anche `send_mfa_disabled_alert`
  (email all'utente) già pronta e mai chiamata.
- **Risolto (2026-09-03)**:
  - **MFA disable** (`api/mfa.py`): `disable_mfa` logga ora
    `mfa_disabled` (severity `warning`, IP, email) e invia
    `send_mfa_disabled_alert` in fire-and-forget via
    `asyncio.create_task` (stesso pattern di
    `user_profile.py:180` per `send_password_changed_alert`; il
    notification service deglutisce già i fallimenti invio — l'email
    non può rompere la response).
  - **Refresh reuse** (`services/refresh_token.py`): il reuse è
    interamente nel service (`validate_and_rotate`, due punti) e
    `api/auth.py:529-559` citato dal piano oggi contiene altro codice
    (linee shiftate). Fix nel funnel unico `_revoke_token_family`
    (chiamato solo sui percorsi di reuse): log di
    `refresh_token_reuse_detected` (severity `warning`) con root
    token_id, revoked_count, client_id e IP. Il service istanzia
    `AuditService()` nel `__init__` (pattern VAPT-130 di
    `user_profile.py`). **Copertura completa**: loggando nel service,
    l'evento copre sia il flusso cookie (`/api/auth/refresh`) sia il
    grant OAuth2 refresh al token endpoint — entrambi passano per
    `validate_and_rotate`.
  - Test: `test_reuse_detection_logs_audit_event`
    (`tests/unit/test_refresh_token.py`) e
    `TestDisableMfaSecurityTrail` (`tests/integration/test_mfa_api.py`,
    con nota: l'override dipendenze deve puntare al
    `get_audit_service` di `api/mfa.py`, non a quello di `api/auth.py`).

---

## TIER 1 — Prima sprint post-launch (10 voci)

| ID | Cosa | Perché conta | Fix in breve |
|---|---|---|---|
| VAPT-060 | Race su registrazione (`register_user`/`invite_user`) ritorna 500 grezzo invece di 400 | Confermato oggi: `api/auth.py:2196` chiama `storage.create_user(user)` senza `try/except ValueError` — combinato con T0-4 (nessun handler globale) un utente che si registra due volte in parallelo vede un errore server generico invece di "email già in uso" | Wrappare in `try/except ValueError` → HTTP 400, come già fa l'endpoint admin equivalente |
| VAPT-061 | `admin.update_user` legge-poi-scrive senza lock: una modifica admin concorrente (reset MFA, cambio scope) può sparire silenziosamente | Su un pannello admin multi-operatore questo produce incoerenze difficili da diagnosticare | `named_lock(f"user:{user_id}")` attorno all'intero handler |
| VAPT-075 / VAPT-076 | ~20 endpoint admin/RBAC/profilo senza `@limiter.limit`, incluse `user-search` (enumerazione), `user-export` (PII bulk), invito utenti | Superficie di brute-force/DoS su path amministrativi | Rigenerare la lista con `grep -nL '@limiter.limit' backend/authglow/api/admin.py` e applicare limiti proporzionati al rischio |
| VAPT-077 | `/api/password/change` a 20/hour, nessun backoff progressivo | Permette molti tentativi di indovinare la password corrente | Scendere a 5/minute o 10/hour + contatore per-utente |
| VAPT-126 | Registrazione pubblica a 5/min per IP = 7200 account/giorno per IP, zero CAPTCHA | Se `allow_public_registration=True` (default), è un vettore di spam email e di accumulo record | Scendere a 2/minute + CAPTCHA/Turnstile, oppure disabilitare la registrazione pubblica di default |
| VAPT-107 | Le notifiche di sicurezza (nuovo login, MFA enable/disable, nuova API key, account bloccato) esistono come funzioni ma non sono mai chiamate | Un cliente enterprise si aspetta queste email come funzionalità di base, non come lavoro futuro | Wireare le 5 funzioni già scritte in `security_notifications.py` nei punti giusti |
| OIDC-001 | Manca `Cache-Control: no-store` + `Pragma: no-cache` su token/introspect/revoke/device (RFC 6749 §5.1, MUST) | Requisito di conformità letterale, rischio di caching accidentale di token da parte di proxy intermedi | Header su 6 endpoint, nessuna logica nuova (vedi `OAUTH2_OIDC_COMPLIANCE_PLAN.md`) |
| OIDC-003 | Proof DPoP non valida l'header `typ: dpop+jwt` (RFC 9449 §4.2, REQUIRED) | Il fix più veloce del lotto — una condizione in più in una funzione già solida | Vedi `OAUTH2_OIDC_COMPLIANCE_PLAN.md` |
| OIDC-004 | Cache di replay (`jti_cache`, usata da DPoP e da client-assertion JWT-bearer) è in memoria per default, senza guard multi-istanza | Su deploy con più worker/pod, la protezione da replay degrada silenziosamente da globale a per-processo — **verifica prima di tutto come giri oggi in produzione**, la severità dipende da questo | Hard-fail o warning esplicito quando `is_production` e `cache_backend == "memory"` |
| VAPT-105 | Due definizioni diverse di "admin" (`scopes` vs ruolo RBAC) tra `admin.py` e `rbac.py` | Un utente può avere accesso a metà della superficie amministrativa e non all'altra metà, in modo inconsistente e sorprendente | Scegliere una definizione canonica (consigliato: ruolo RBAC) e usarla ovunque |

---

## TIER 2 — Backlog di hardening (non bloccante)

Raggruppato per area, con gli ID originali per riferimento — il
dettaglio completo di ciascuno è già in `VAPT_FIX_PLAN.md`, non lo
riscrivo qui:

- **Header/CORS fine-tuning**: VAPT-067 (COOP/COEP/CORP mancanti),
  VAPT-121 (HSTS senza `preload`), VAPT-122 (CORS accetta tutti i
  metodi di default), VAPT-123 (default include localhost).
- **Input validation**: VAPT-088/089/090/091/092 (telefono, nomi,
  campi enum, IP allowlist, header injection via `first_name`) — nessuno
  di questi è sfruttabile in modo grave, ma sono tutti fix meccanici a
  basso rischio, buoni da smaltire in batch.
- **Concorrenza fine (TOCTOU minori)**: VAPT-059, VAPT-063
  (*richiede un recheck: il codice è stato rifattorizzato dopo che
  questa voce è stata scritta*), VAPT-064, VAPT-065.
- **Sessioni/JWT**: VAPT-109 (ID token senza `token_type`), VAPT-110
  (nessun leeway sull'orologio), VAPT-111 (sessione MFA non legata a
  IP/UA), VAPT-112 (un admin degradato mantiene i vecchi scope fino a
  scadenza del token), VAPT-113 (rara race sulla rotazione refresh
  token), VAPT-116 (secret TOTP in chiaro senza `no-store`).
- **MFA minori**: VAPT-053 (fingerprint dispositivo debole dietro
  NAT), VAPT-054 (nessun lockout su TOTP, solo su backup code),
  VAPT-115 (dispatch fragile codice TOTP/backup code).
- **Supply chain / build**: VAPT-093 (manca `dependabot.yml`),
  VAPT-094 (gitleaks pinnato a tag mutabile invece di SHA), VAPT-098
  (nessun SBOM), VAPT-099/100/101 (pinning versioni allentato),
  VAPT-133 (dev tooling non pinnato), VAPT-134 (recharts trascina
  Redux).
- **Logging/hygiene**: VAPT-127 (warning CORS su stderr, può perdersi
  in container), VAPT-128 (config structlog non centralizzata),
  VAPT-129 (nessun filtro per livello di log), VAPT-132 (log injection
  teorica via scope con newline).
- **INFO (10 voci)**: `security.txt` mancante, key size hardcoded,
  federazione senza allowlist di issuer, e altre voci di igiene — vedi
  sezione INFO del plan originale, nessuna è urgente.

---

## Falsi allarmi da chiudere nel VAPT_FIX_PLAN.md originale

Verificando il codice per costruire questo piano ho trovato tre voci
segnate `[ ]` (aperte) che in realtà **sono già risolte** — vale la
pena spuntarle nel documento originale così il prossimo che lo legge
non perde tempo a riverificarle:

- **VAPT-068** (CORS wildcard) — in realtà già corretto per il caso
  `cors_allowed_origins == "*"` + credentials: `core/config.py:667-694`
  ha un `model_validator` che fa hard-fail in produzione. Resta aperto
  solo il sotto-caso, meno grave, di `cors_allowed_headers == "*"`
  (che comunque per specifica Fetch è un no-op quando `credentials=true`,
  quindi non è realmente sfruttabile — solo un warning fuorviante).
- **VAPT-095** (Dockerfile come root) — già corretto:
  `backend/Dockerfile:17` ha `USER appuser`.
- **VAPT-097** (`.dockerignore` mancante) — già corretto: esiste sia
  `.dockerignore` in root sia `backend/.dockerignore`.

---

## Ordine di lavoro consigliato

1. **Tier 0, nell'ordine T0-2 → T0-3 → T0-6 → T0-5 → T0-1 → T0-4** —
   dal più rapido al più impegnativo. T0-1 (CSRF) e T0-4 (exception
   handler) sono i due che richiedono più attenzione progettuale;
   fanne uno alla volta con test dedicati.
2. Prima di iniziare **OIDC-004** in Tier 1, verifica la topologia di
   deploy reale (quanti worker/istanze) — determina se è davvero Tier 1
   o va promosso a Tier 0.
3. Tier 1 nell'ordine della tabella è già ragionevole (i fix più
   piccoli — OIDC-003, VAPT-105 — in cima).
4. Tier 2: smaltiscilo in batch tematici quando conviene, non è sulla
   strada critica del go-live.

## Changelog

- 2026-09-03: creazione del documento. 6 voci Tier 0, 10 voci Tier 1,
  backlog Tier 2 raggruppato per area. 3 falsi allarmi identificati e
  documentati per la correzione del plan originale.
- 2026-09-03: **T0-2 chiuso** — `enable_docs` default off in
  produzione via before-validator (opt-in esplicito rispettato con
  warning); toggle admin docs documentato come inefficace (nota in
  sezione T0-2). Verificato: `test_config.py` 51/51, suite completa
  senza failure, ruff/mypy puliti.
- 2026-09-03: **T0-3 chiuso** — hard-fail al boot in produzione su
  default passkey localhost/vuoti (`_validate_passkey_defaults_for_production`).
  "Perché blocca" corretto nel documento: le cerimonie WebAuthn usano
  origin dinamico dagli header, i setting alimentano solo le route
  admin di listing (rischio reale = config fuorviante + mine futura).
  Verificato: suite completa 2579 passed, ruff/mypy puliti
  (+ auto-fix I001 pre-esistenti in `test_cookie_auth.py`).
- 2026-09-03: **T0-6 chiuso** — audit `mfa_disabled` + email
  `send_mfa_disabled_alert` wireata in `disable_mfa`;
  `refresh_token_reuse_detected` loggato nel funnel
  `_revoke_token_family` (copre cookie refresh e OAuth2 token
  endpoint). 2 test nuovi; suite completa 2581 passed,
  ruff/mypy puliti.
- 2026-09-03: **T0-5 chiuso** — lifetime refresh token da
  `refresh_token_expire_days` ovunque: 4 call site (federation
  scoperto in verifica) + default del metodo con fallback config
  (la rotazione ereditava il 30 hardcoded). Guardia di regressione
  source-scan. 3 test nuovi; suite completa 2584 passed,
  ruff/mypy puliti.
- 2026-09-03: **T0-1 chiuso** — premessa corretta: il CSRF era già
  enforcementato via middleware globale (non via `require_csrf`).
  Trovato e risolto un **bug funzionale**: il doppio enforcement
  (middleware + check inline in authorize) con token one-time
  rendeva impossibile l'authorize da utente loggato (sempre 403).
  validate_token non consumante, enforcement unico nel middleware
  (gate esteso a refresh + csrf_session_id, bypass credenziali
  esplicite, audit su mismatch), frontend con cache+retry. Probe
  empirica: authorize via cookie 200 (prima 403), attacco senza
  header 403. 15 test nuovi/aggiornati; suite completa 2596
  passed.
- 2026-09-03: **T0-4 chiuso — TIER 0 COMPLETO (6/6)**. Handler
  globale (`register_global_error_handler`, audit + 500 generico
  stabile) e 5 siti leak `str(e)` genericizzati (passkey ×2,
  federation ×3) con audit server-side. 2 test nuovi + 2 aggiornati
  al contratto generico; suite completa 2598 passed,
  ruff/mypy puliti.
