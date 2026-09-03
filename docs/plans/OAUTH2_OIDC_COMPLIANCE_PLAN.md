# OAuth2/OIDC Compliance Audit — AuthGlow (2026-09-03)

> **Scope**: conformità a RFC 6749 (OAuth2 Core), RFC 6750 (Bearer Token
> Usage), RFC 7009 (Revocation), RFC 7636 (PKCE), RFC 7662
> (Introspection), RFC 7523 (JWT Bearer Client Auth), RFC 8414 /
> OIDC Discovery, RFC 8628 (Device Authorization Grant), RFC 9068 (JWT
> Access Tokens), RFC 9449 (DPoP), OIDC Core 1.0 e RP-Initiated Logout.
> **Metodo**: lettura diretta del codice corrente (`backend/authglow/`),
> non della sola documentazione. Ogni finding è stato verificato riga per
> riga nel repository, non dedotto da `docs/`.
> **Relazione con `docs/plans/VAPT_FIX_PLAN.md`**: quel file copre già in
> modo eccellente la maggior parte della superficie OAuth2/OIDC (PKCE
> obbligatorio, `state` ad alta entropia, `aud` binding, redirect_uri
> exact-match, scope narrowing sul refresh, RP-Initiated Logout,
> Device Grant RFC 8628 completo, DPoP con `ath`/`jti`/`htm`/`htu`).
> Questo documento **non duplica** quel lavoro: contiene solo i gap di
> conformità che non erano ancora tracciati da nessuna parte.
> **Stato**: 0/5 chiusi. Nessuno di questi item è "critico" nel senso
> VAPT (nessuno è direttamente sfruttabile per un takeover) — sono gap
> di conformità alla lettera delle RFC che riducono la difesa in
> profondità o la interoperabilità con client/resource server terzi.

## Come usare questo file

Ogni finding ha un ID stabile `OIDC-NNN`. Spunta `[x]` quando risolto e
aggiungi una nota (commit, o "deferred — motivazione"). Sono pensati per
essere completati **uno alla volta**, in qualsiasi ordine — non ci sono
dipendenze tra loro.

## Riepilogo

| ID | Severità | RFC | Stato |
|---|---|---|---|
| OIDC-001 | MEDIUM | RFC 6749 §5.1 (MUST) | [ ] |
| OIDC-002 | MEDIUM | RFC 9068 (SHOULD, anti type-confusion) | [ ] |
| OIDC-003 | MEDIUM | RFC 9449 §4.2 (REQUIRED) | [ ] |
| OIDC-004 | MEDIUM/HIGH* | RFC 9449 §11.1 / RFC 7523 (guidance) | [ ] |
| OIDC-005 | INFO | Estensioni opzionali (PAR/JAR/RFC 8707) | [ ] |

\* dipende dalla topologia di deploy — vedi dettaglio.

---

## OIDC-001 — Manca `Cache-Control: no-store` / `Pragma: no-cache` sulle risposte con token

- **Severità**: MEDIUM
- **RFC**: RFC 6749 §5.1 — *"The authorization server MUST include the
  HTTP Cache-Control response header field with a value of 'no-store'
  in any response containing tokens, credentials, or other sensitive
  information, as well as the Pragma response header field with a
  value of 'no-cache'."* Requisito **MUST**, non opzionale.
- **Location**:
  - `backend/authglow/api/auth.py:1109` (`POST /oauth2/token`)
  - `backend/authglow/api/auth.py:1751` (`POST /api/token/api-key`)
  - `backend/authglow/api/auth.py:1853` (`POST /api/auth/refresh`)
  - `backend/authglow/api/oauth2_advanced.py:65` (`POST /oauth2/revoke`)
  - `backend/authglow/api/oauth2_advanced.py:162` (`POST /oauth2/introspect`)
  - `backend/authglow/api/device_auth.py:55` (`POST /oauth2/device/authorize`)
- **Descrizione**: ho verificato `middleware/security_headers.py` (il
  middleware globale che aggiunge CSP/HSTS/X-Frame-Options ecc.) e
  nessuno degli endpoint sopra imposta `response.headers[...]` per
  Cache-Control/Pragma. L'unico posto nel codebase che imposta
  correttamente `Cache-Control: private, max-age=0, no-cache` è
  l'endpoint UserInfo (`oidc.py:308`) — ma anche lì manca `no-store` in
  senso letterale, e comunque UserInfo non è il caso più critico (il
  caso critico sono le risposte che *contengono* il token). Senza questi
  header, un proxy intermedio o la cache del browser potrebbe
  memorizzare access/refresh token nella risposta del token endpoint.
- **Fix suggerito**: aggiungere un piccolo helper riusabile, es.
  ```python
  def _no_store_headers(response: Response) -> None:
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"
  ```
  e chiamarlo in ognuno dei 6 endpoint sopra (serve aggiungere il
  parametro `response: Response` alla firma dove non è già presente,
  es. `oauth2_advanced.py` e `device_auth.py` non lo hanno). In
  alternativa, centralizzarlo nel middleware esistente aggiungendo un
  set di path prefix (`/oauth2/token`, `/oauth2/revoke`,
  `/oauth2/introspect`, `/oauth2/device/authorize`, `/api/token`,
  `/api/auth/refresh`) che ricevono sempre l'header, sul modello di
  come il middleware già gestisce `/docs`/`/redoc` in modo differenziato.
- **Test da aggiungere**: un test per endpoint che verifica
  `response.headers["Cache-Control"] == "no-store"` e
  `response.headers["Pragma"] == "no-cache"`.

---

## OIDC-002 — Access token senza header `typ: at+jwt` (RFC 9068)

- **Severità**: MEDIUM
- **RFC**: RFC 9068 §2.1 registra il tipo di media `at+jwt` proprio per
  gli access token JWT, così un resource server può rifiutare a priori
  un JWT che non è tipizzato come access token (es. un ID token o un
  refresh token JWT presentato per errore o per attacco). È una
  raccomandazione **SHOULD** con un chiaro razionale di sicurezza
  (mitigare la confusione tra tipi di JWT).
- **Location**: `backend/authglow/services/jwt.py:232-236` — l'unico
  punto che chiama `jwt.encode(...)` per **tutti e tre** i tipi di
  token (`create_access_token:325`, `create_refresh_token:398`,
  `create_id_token:506` condividono lo stesso helper di basso livello),
  passando sempre lo stesso `headers={"kid": self._active_kid}`. Il
  campo `typ` non viene mai impostato esplicitamente, quindi resta il
  default di PyJWT (`"JWT"`) per ogni tipo di token emesso.
- **Descrizione**: oggi un access token, un refresh token JWT e un ID
  token sono indistinguibili a livello di header JOSE — l'unico modo
  per un resource server di sapere "questo è un access token" è
  ispezionare i claim (`aud`, `scope`), non l'header. Questo è
  esattamente il vettore che RFC 9068 vuole chiudere.
- **Fix suggerito**: passare `headers={"kid": ..., "typ": "at+jwt"}`
  solo nel path di `create_access_token`, lasciando `"JWT"` (o
  omettendo `typ`) per refresh e ID token. Nel verificatore
  (`decode_token`), se il chiamante indica che si aspetta un access
  token, validare `unverified_header.get("typ") == "at+jwt"` prima di
  procedere — con un percorso di compatibilità per i token già emessi
  senza questo header (altrimenti tutti i token esistenti diventano
  invalidi al deploy).
- **Nota di rollout**: essendo un cambio di formato del token, va
  accompagnato da un periodo di transizione (accettare sia il vecchio
  `"JWT"` sia il nuovo `"at+jwt"` in lettura per la durata di vita
  massima di un access token, poi stringere).

---

## OIDC-003 — Manca la validazione dell'header `typ: dpop+jwt` sulla proof DPoP

- **Severità**: MEDIUM
- **RFC**: RFC 9449 §4.2 — il campo header `typ` della proof DPoP è
  **REQUIRED** e deve valere `dpop+jwt` esplicitamente *"to explicitly
  type the DPoP proof JWT ... to prevent JWTs from being confused for
  other purposes"*.
- **Location**: `backend/authglow/services/dpop.py`, funzione
  `verify_dpop_proof` (righe 211-249). L'header non firmato viene letto
  e controllato per `alg` (riga 216-221) e `jwk` (riga 222-224), ma
  **non** per `typ`.
- **Descrizione**: l'implementazione DPoP qui è già molto solida
  (verifica `ath`, `htm`, `htu` normalizzato, finestra `iat`, replay via
  `jti`) — questo è l'unico controllo REQUIRED dalla spec che manca a
  livello di header. Senza di esso, un JWT con uno scopo diverso ma
  firmato con la stessa chiave EC P-256 e contenente per coincidenza i
  claim richiesti (`htm`, `htu`, `iat`, `jti`) potrebbe in teoria essere
  accettato come proof DPoP.
- **Fix suggerito**: subito dopo il controllo su `alg` (riga ~221),
  aggiungere:
  ```python
  typ = unverified_header.get("typ")
  if typ != "dpop+jwt":
      raise _dpop_error(
          "invalid_typ",
          f"DPoP proof typ must be 'dpop+jwt', got {typ!r}",
      )
  ```
- **Test da aggiungere**: un caso che genera una proof valida in tutto
  tranne il `typ` (es. `typ="JWT"` o assente) e verifica che venga
  rifiutata con 401 `invalid_dpop_proof`.

---

## OIDC-004 — Cache di replay-protection (DPoP + client assertion JWT-bearer) in memoria per default, senza guard multi-istanza

- **Severità**: MEDIUM in singola istanza, **HIGH** se il deploy reale
  gira già multi-worker/multi-istanza senza `CACHE_BACKEND=redis`
  esplicito — vale la pena verificare la configurazione di produzione
  prima di assegnare la severità definitiva.
- **RFC**: non è una violazione letterale di una singola RFC, ma mina
  l'assunzione su cui si basano sia RFC 9449 (DPoP, uso di `jti` per il
  replay) sia RFC 7523 (JWT Bearer client authentication, stesso
  meccanismo). RFC 9449 §11.1 discute esplicitamente la necessità che
  lo storage dei `jti` sia condiviso in un sistema distribuito.
- **Location**:
  - `backend/authglow/core/cache.py` — `InMemoryCacheBackend` è il
    default; il backend Redis esiste (`cache_backend: str = "memory"`
    in `core/config.py:389`) ma non è forzato in produzione.
  - `backend/authglow/services/dpop.py:123-136`
    (`replay_protect_dpop_jti`) — usa `jti_cache` per il replay delle
    proof DPoP.
  - `backend/authglow/services/client_jwt_auth.py:110-123`
    (`replay_protect_jti`) — stesso `jti_cache`, per il replay delle
    client assertion JWT (`private_key_jwt`/`client_secret_jwt`, RFC
    7523).
- **Descrizione**: con il backend di default (`memory`), ogni processo
  worker ha la propria `TTLCache` locale. Se l'app gira con più worker
  Uvicorn/Gunicorn sulla stessa macchina (comunissimo) o su più
  istanze/pod, una proof DPoP o una client assertion già usata su un
  worker può essere riproposta con successo su un altro worker, perché
  il secondo worker non ha mai visto quel `jti`. La protezione da replay
  non fallisce in modo rumoroso: degrada silenziosamente da "globale" a
  "per singolo processo", il che è particolarmente insidioso perché
  passa tutti i test funzionali (single-worker) e si manifesta solo in
  produzione sotto carico reale. Da notare: il blacklist dei
  *access token revocati* (`services/auth/token_blacklist.py`) **non**
  ha questo problema — è già persistito su disco/filesystem condiviso
  proprio per garantire la visibilità multi-istanza; qui manca lo stesso
  trattamento solo per i due `jti_cache` di replay.
- **Fix suggerito** (in ordine di preferenza):
  1. In `core/config.py`, aggiungere un controllo hard-fail in
     `is_production` (mirror di quanto già fatto per
     `oauth2_client_secret` di default, VAPT-014): se
     `is_production=True` e sono configurati più worker (o più in
     generale sempre, per fail-safe) e `cache_backend == "memory"`,
     rifiutare l'avvio con un errore esplicito che indica di impostare
     `CACHE_BACKEND=redis`.
  2. In alternativa più permissiva: loggare un `logger.warning(...)`
     ben visibile all'avvio quando `cache_backend == "memory"` e
     `is_production=True`, spiegando l'impatto esatto (replay
     protection non condivisa tra istanze).
  3. Documentare esplicitamente in `docs/QUICK_SETUP.md` /
     `SECURITY.md` che `CACHE_BACKEND=redis` è un prerequisito per
     qualunque deploy con più di un processo worker.
- **Prima di implementare**: verifica come AuthGlow viene effettivamente
  distribuito oggi (singolo worker? Gunicorn con più worker? più pod
  Kubernetes?) — la severità e l'urgenza del fix dipendono interamente
  da questo.

---

## OIDC-005 — Estensioni opzionali non implementate (informativo, non un difetto)

- **Severità**: INFO
- **Descrizione**: nessuno di questi è richiesto da OAuth2 Core o OIDC
  Core; li segnalo solo per completezza del quadro, nel caso in futuro
  serva puntare a un profilo più stringente (es. FAPI 2.0 per clienti
  bancari/PA):
  - **PAR** (Pushed Authorization Requests, RFC 9126) — non
    implementato; `request_uri_parameter_supported: bool = False` è
    hardcoded in `models/oidc.py:120`.
  - **JAR** (JWT-Secured Authorization Request, RFC 9101) — non
    implementato; stesso file, `require_request_uri_registration`.
  - **Resource Indicators** (RFC 8707, parametro `resource`) — nessuna
    occorrenza nel codebase; utile solo se in futuro un singolo AS
    dovrà emettere token per più resource server distinti con `aud`
    differenziato in modo esplicito dal client.
  - **mTLS client authentication** (RFC 8705) — non implementato; DPoP
    (RFC 9449) copre già lo stesso caso d'uso (sender-constraining) in
    modo applicativo, quindi non è necessariamente un gap se DPoP resta
    il meccanismo scelto.
- **Fix suggerito**: nessuna azione ora. Riaprire questo item solo se
  emerge un requisito concreto (es. un cliente FAPI 2.0) — non
  implementare in anticipo senza un consumer reale.

---

## Ordine suggerito

Non ci sono dipendenze tra i 4 item azionabili. Il più veloce da chiudere
è **OIDC-003** (una condizione in più in una funzione già scritta bene).
**OIDC-001** è il secondo più veloce (header su 6 endpoint, nessuna
logica nuova). **OIDC-002** richiede un minimo di attenzione al rollout
(compatibilità con token già emessi). **OIDC-004** richiede prima di
tutto capire come AuthGlow è distribuito in produzione, quindi è bene
verificarlo per primo anche se l'implementazione arriva per ultima.

## Changelog

- 2026-09-03: creazione del documento, 5 finding (OIDC-001..005), 0
  chiusi.
