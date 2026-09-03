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

### T0-1 — [ ] CSRF costruito ma non collegato a nessun endpoint (VAPT-066)

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

### T0-2 — [ ] `enable_docs=True` di default, non legato all'ambiente (VAPT-070)

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

### T0-3 — [ ] `passkey_rp_id` / `passkey_origin` di default puntano a `localhost` (VAPT-069)

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

### T0-4 — [ ] Nessun exception handler globale + errori verbosi in risposta (VAPT-074 + VAPT-073)

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

### T0-5 — [ ] Refresh token: 30 giorni hardcoded, la config viene ignorata (VAPT-058)

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

### T0-6 — [ ] Nessun audit trail su disable MFA e su reuse-detection dei refresh token (VAPT-056 + VAPT-057)

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
