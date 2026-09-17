---
type: plan
status: active
ids: AUTH-NNN
---

# AuthGlow Security Remediation Plan

Ogni remediation è tracciata con una checkbox `[ ]` nell'elenco delle priorità. Segnare `[x]` solo dopo aver soddisfatto i criteri di accettazione e completato le verifiche previste, aggiungendo un riferimento alle evidenze.

Gli ID delle remediation e gli ID dei test appartengono a due elenchi distinti: mantenere i riferimenti indicati nelle singole sezioni.

Repository: `davideconsonni/authglow`  
Scope: Backend OAuth2/OIDC, authentication, sessions, MFA/passkey, tokens, admin APIs, webhooks, deployment security  
Assessment baseline: security review del branch `main`

## Obiettivo

Portare AuthGlow da una security posture buona ma non ancora adeguata a un Identity Provider internet-facing a una postura adatta a deployment production multi-instance.

Le remediation devono seguire questo ordine:

### P0
- [x] AUTH-001: Passkey login per utente disattivato
  <!-- DONE: fix + regression test in test_passkey.py::TestCompleteAuthenticationAccountStatus (attivo, inattivo 401, sospeso 423 con deadline UTC, sospensione scaduta) + frontend formatta la data in ora locale. Call-site revisionati: password/federato/MFA allineati alla stessa risposta 423 strutturata. -->
- [ ] AUTH-002: Replay protection distribuita per client assertion / DPoP
- [ ] AUTH-003: Rate limiting distribuito

### P1
- [ ] AUTH-004: Eliminazione plaintext temporary secrets
- [x] AUTH-005: Strict OAuth client authentication method
  <!-- DONE: verify_client + _authenticate_client_at_token_endpoint enforce the exact registered method (basic/post/JWT/none, one method per request); DCR/admin require public_jwk for private_key_jwt. Tests: TestVerifyClientStrictMethod (7) + TestAuthenticateClientStrictMethod (8) + channel fixes across conformance/integration suites. -->
- [ ] AUTH-006: Passkey RP ID / Origin configuration
- [ ] AUTH-007: Webhook SSRF / DNS rebinding
- [ ] AUTH-008: Password-reset secret exposure nell'admin API

### P2
- [ ] AUTH-009: Access token esposto nel browser OAuth flow
- [ ] AUTH-010: Setup token handling
- [ ] AUTH-011: Dependency/security CI
- [ ] AUTH-012: Security regression suite completa

---

# AUTH-001 — Inactive user bypass tramite Passkey

## Severity
HIGH

## Problema

Il login Passkey verifica correttamente la credenziale WebAuthn ma il percorso di autenticazione non verifica `user.is_active` prima di emettere access e refresh token.

Un utente disattivato potrebbe quindi autenticarsi usando una passkey ancora valida.

## Area

`backend/authglow/api/passkey.py`

Funzione da verificare:

`complete_authentication()`

## Fix richiesto

Dopo il recupero dell'utente e prima dell'emissione dei token verificare esplicitamente:

```python
if not user.is_active:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Inactive user",
    )
```

Verificare anche la semantica di eventuali stati come:

- `is_active`
- `suspended_until`
- eventuale revoca account

La regola deve essere coerente con tutti gli altri authentication flow.

## Acceptance criteria

- Utente attivo + passkey valida → login consentito
- Utente disattivato + passkey valida → login negato
- Utente sospeso → comportamento coerente con il resto dell'authentication stack
- Nessun access token emesso
- Nessun refresh token emesso
- Evento di audit presente se previsto dal modello di auditing

## Test

Aggiungere regression test:

`AUTH-001`

Scenario:

1. creare user
2. registrare passkey
3. disattivare user
4. eseguire authentication con passkey valida
5. verificare HTTP 401
6. verificare che nessun token venga creato

---

# AUTH-002 — Replay protection distribuita

## Severity
HIGH

## Problema

La replay protection per:

- OAuth `client_assertion`
- DPoP proof

usa cache/repository che risultano process-local.

In deployment con più istanze dietro load balancer:

```text
Request 1 → Instance A → jti registrato
Request 2 → Instance B → jti non conosciuto
```

Lo stesso assertion/proof può quindi essere riutilizzato.

## Aree

- `backend/authglow/services/client_jwt_auth.py`
- `backend/authglow/services/dpop.py`

## Fix richiesto

Introdurre storage condiviso con operazione atomica:

```text
SET key value NX EX ttl
```

Redis è una soluzione naturale.

La semantica richiesta è:

```text
first use  → accepted
second use → rejected
```

indipendentemente dall'istanza che riceve la richiesta.

## Acceptance criteria

- Replay sulla stessa istanza → reject
- Replay su istanza diversa → reject
- Due richieste concorrenti con stesso JTI → una sola accettata
- TTL coerente con lifetime dell'assertion/proof
- Failure del distributed store non deve trasformarsi silenziosamente in "accept all"

## Test

`AUTH-006`

Client assertion replay cross-instance.

`AUTH-007`

DPoP replay cross-instance.

Aggiungere test concorrenti se l'architettura lo consente.

---

# AUTH-003 — Rate limiting distribuito

## Severity
HIGH

## Problema

Il rate limiter attuale appare principalmente process-local.

In un deployment multi-worker:

```text
100 attempts → instance A
100 attempts → instance B
100 attempts → instance C
```

il limite effettivo diventa moltiplicato per il numero di processi/istanze.

Questo interessa soprattutto:

- login
- password reset
- MFA
- passkey
- device authentication
- token endpoint
- API key authentication

## Area

`backend/authglow/core/rate_limit.py`

## Fix richiesto

Usare uno storage condiviso oppure rate limiting a livello gateway.

Preferenza:

```text
Application
    ↓
Shared Redis
```

con chiavi coerenti per:

- IP
- username/account
- client_id
- endpoint
- eventualmente combinazioni di questi

Non affidarsi esclusivamente all'IP.

## Acceptance criteria

- Limite identico indipendentemente dall'istanza
- Atomicità degli incrementi
- TTL corretto
- Nessun bypass tramite round-robin tra istanze
- Distinzione tra account-based e IP-based throttling
- comportamento definito in caso di Redis unavailable

## Test

`AUTH-008`

Eseguire N richieste distribuite su almeno due worker e verificare che il limite sia globale.

---

# AUTH-004 — Plaintext temporary secrets

## Severity
MEDIUM/HIGH

## Problema

Alcuni temporary token/code vengono persistiti in chiaro.

In particolare:

- MFA session token
- consent session token
- email/phone verification code
- password reset code

L'HMAC lookup protegge il lookup/index ma non il valore contenuto nel record.

## Aree

- `backend/authglow/services/session.py`
- `backend/authglow/repositories/file/session.py`
- password reset models/services

## Obiettivo

Un attaccante che ottenga accesso ai file/session store non deve poter convertire direttamente i record in bearer credentials.

## Pattern desiderato

Per token:

```text
lookup = HMAC(token)
verifier = hash(token)
```

Persistire:

```text
lookup
verifier
metadata
expiry
```

Non:

```text
plaintext token
```

Per codici brevi usare un verifier appropriato e protezioni contro brute force.

## Acceptance criteria

- Nessun session token persistito in plaintext
- Nessun verification code persistito in plaintext
- Nessun reset code persistito in plaintext
- File repository e qualsiasi eventuale database repository hanno la stessa semantica
- I log non contengono i valori

## Test

`AUTH-009` concurrent password-reset redemption

`AUTH-011` concurrent email-code redemption

Aggiungere test che leggano direttamente lo storage e verifichino che il secret originale non sia presente.

---

# AUTH-005 — Strict OAuth client authentication method

## Severity
MEDIUM/HIGH

## Problema

`OAuth2Service.verify_client()` presenta una compatibilità legacy in cui la presenza di `client_secret` può consentire authentication anche quando il client è registrato con un metodo differente.

Esempio problematico:

```text
registered:
private_key_jwt

request:
client_secret_basic
```

Il server deve applicare il metodo dichiarato dal client.

## Area

`backend/authglow/services/oauth2.py`

e

`backend/authglow/models/oauth_client.py`

## Fix

Implementare una policy esplicita:

```text
token_endpoint_auth_method
        ↓
required authentication mechanism
```

Esempi:

```text
client_secret_basic → solo basic
client_secret_post  → solo post
private_key_jwt     → solo JWT assertion
client_secret_jwt   → solo JWT assertion
none                → nessun secret
```

## Acceptance criteria

Un client configurato:

`private_key_jwt`

non può autenticarsi tramite:

`client_secret_basic`

anche se un client secret esiste.

## Test

`AUTH-005`

Provare ogni combinazione non consentita.

---

# AUTH-006 — Passkey RP ID / Origin

## Severity
MEDIUM

## Problema

Il RP ID/origin WebAuthn viene derivato dinamicamente da:

- `Origin`
- `Host`

Questo rende il trust boundary dipendente dalla request.

Per un Identity Provider è preferibile una configurazione esplicita.

## Area

Passkey service / configuration.

## Target

Configurazione tipo:

```text
PASSKEY_RP_ID=id.example.com

PASSKEY_ORIGINS=https://id.example.com
```

Eventualmente supportare una lista di origin esplicitamente configurati.

## Acceptance criteria

- Host arbitrario non modifica il RP ID
- Origin non configurato viene rifiutato
- reverse proxy headers sono gestiti solo se esplicitamente trusted
- WebAuthn continua a funzionare con il dominio configurato

## Test

`AUTH-012`

Malicious Passkey Origin.

Testare anche:

- Host injection
- `X-Forwarded-Host`
- `X-Forwarded-Proto`
- Origin non allowlisted

---

# AUTH-007 — Webhook SSRF / DNS rebinding

## Severity
MEDIUM

## Problema

La protezione SSRF:

1. risolve DNS
2. verifica che l'IP sia pubblico
3. effettua successivamente la request usando hostname

Questo introduce una possibile TOCTOU/DNS rebinding:

```text
validation → public IP

request → private IP
```

Inoltre è necessario verificare la gestione dei redirect.

## Area

`backend/authglow/services/webhook_dispatcher.py`

`backend/authglow/core/http_client.py`

## Fix

Preferibile:

```text
URL
 ↓
resolve
 ↓
validate all IPs
 ↓
connect to validated IP
```

mantenendo correttamente:

- Host header
- TLS SNI
- certificate validation

Alternativa robusta:

egress proxy con policy SSRF centralizzata.

## Acceptance criteria

Bloccare:

- `127.0.0.1`
- RFC1918
- link-local
- metadata endpoints
- IPv6 private/link-local
- DNS rebinding
- redirect verso indirizzo privato

Definire esplicitamente se `insecure=True` deve essere eliminato.

## Test

`AUTH-013`

DNS rebinding.

`AUTH-014`

redirect verso private IP.

---

# AUTH-008 — Password reset data exposure nell'admin API

## Severity
MEDIUM

## Problema

L'admin endpoint espone direttamente `PasswordResetToken`.

Il modello contiene informazioni che non dovrebbero essere restituite a un administrator come DTO generico:

- `token_lookup`
- `token_hash`
- `reset_code`

Il reset code può essere utilizzato per completare un reset.

## Area

`backend/authglow/api/password_reset.py`

## Fix

Creare un DTO specifico per admin.

Esempio:

```text
token_id
user_id
created_at
expires_at
is_used
```

Eventualmente:

```text
ip_address
user_agent
```

solo se realmente necessari.

Mai esporre:

```text
token_hash
token_lookup
reset_code
```

## Test

`AUTH-017`

Verificare che l'admin API non restituisca alcun credential material.

---

# AUTH-009 — Access token esposto nel browser OAuth flow

## Severity
MEDIUM

## Problema

Nel browser authentication flow vengono utilizzati cookie `httpOnly`, ma viene anche restituito `access_token_response`.

Questo significa che JavaScript può potenzialmente ottenere il bearer token.

Se l'obiettivo del flow browser è:

```text
browser → httpOnly session cookie
```

non dovrebbe essere necessario esporre il bearer token al JavaScript.

## Area

`backend/authglow/api/auth.py`

e browser authorization flow.

## Decisione da prendere

Separare chiaramente:

### OAuth client

Riceve normalmente:

```text
access_token
refresh_token
```

### First-party browser session

Riceve:

```text
httpOnly secure cookie
```

senza bearer token nel response body.

## Acceptance criteria

- OAuth client flow invariato
- browser session non espone access token a JS
- cookie mantiene tutte le proprietà di sicurezza attuali

---

# AUTH-010 — Setup token

## Severity
MEDIUM

## Problema

Il bootstrap setup token:

- viene scritto su filesystem
- viene loggato
- non risulta avere permission hardening esplicito

Un log collector o chiunque abbia accesso ai log potrebbe ottenere una credential valida.

## Area

`backend/authglow/api/setup.py`

## Fix

Production:

```text
SETUP_TOKEN
```

fornito tramite secret management.

Evitare:

```text
logger.info("setup token = %s", token)
```

Filesystem:

```text
0600
```

se il file è necessario.

Dopo bootstrap:

```text
setup disabled
```

## Test

`AUTH-018`

Verificare che il setup token non appaia:

- nei log
- nei response non necessari
- in file con permission troppo permissive

---

# AUTH-011 — Security CI

## Severity
MEDIUM

## Problema

La dependency audit pipeline utilizza `pip-audit` con:

```text
continue-on-error: true
```

Questo significa che la presenza di vulnerability non blocca necessariamente il build.

## Area

`.github/workflows/test.yml`

## Target pipeline

Ogni PR/push:

```text
pytest
ruff
mypy
pip-audit
npm audit / equivalent
Semgrep
secret scanning
dependency review
```

Le vulnerability High/Critical devono essere gestite come failure, salvo eccezione esplicita e documentata.

## Acceptance criteria

Una PR con una vulnerabilità High/Critical non accettata deve fallire la security pipeline.

---

# AUTH-012 — Security regression suite

## Obiettivo

Trasformare l'assessment in una suite permanente.

## Test minimi

- [x] AUTH-001 inactive user + existing passkey
  <!-- Coperto da test_passkey.py::TestCompleteAuthenticationAccountStatus -->
- [ ] AUTH-002 refresh token used as API bearer
- [ ] AUTH-003 ID token used as API bearer
- [ ] AUTH-004 client A token against client B
- [x] AUTH-005 client_secret against private_key_jwt client
  <!-- Coperto da TestVerifyClientStrictMethod + TestAuthenticateClientStrictMethod -->
- [ ] AUTH-006 replay client_assertion on instance B
- [ ] AUTH-007 replay DPoP on instance B
- [ ] AUTH-008 rate-limit bypass across workers
- [ ] AUTH-009 concurrent password-reset redemption
- [ ] AUTH-010 concurrent authorization-code redemption
- [ ] AUTH-011 concurrent email-code redemption
- [ ] AUTH-012 malicious Passkey Origin
- [ ] AUTH-013 webhook DNS rebinding
- [ ] AUTH-014 webhook redirect to private IP
- [ ] AUTH-015 inactive user + existing access token
- [ ] AUTH-016 revoked user + cached user object
- [ ] AUTH-017 reset-code disclosure through admin API
- [ ] AUTH-018 setup-token disclosure through logs

---

# Ordine di implementazione consigliato

## Sprint / Sessione 1

### AUTH-001
Inactive passkey user

### AUTH-005
Strict client authentication method

Questi sono relativamente circoscritti e devono essere chiusi prima di lavorare sulle parti infrastrutturali.

---

## Sessione 2

### AUTH-002
Distributed replay protection

### AUTH-003
Distributed rate limiting

Questi richiedono una decisione architetturale su Redis/shared state.

---

## Sessione 3

### AUTH-004
Temporary secrets

Fare un audit completo di:

```text
sessions
MFA
consent
email verification
phone verification
password reset
device auth
OAuth temporary state
```

L'obiettivo è avere una policy unica:

> Nessun bearer credential o verification secret temporaneo viene persistito in plaintext.

---

## Sessione 4

### AUTH-006
Passkey RP/origin

### AUTH-007
Webhook SSRF

Sono entrambi trust-boundary issues e meritano test dedicati.

---

## Sessione 5

### AUTH-008
Admin password-reset exposure

### AUTH-009
Browser token exposure

### AUTH-010
Setup token

---

## Sessione 6

### AUTH-011
Security CI

### AUTH-012
Complete regression suite

---

# Regola per ogni remediation

Ogni sessione deve produrre:

- [ ] Root cause
- [ ] Threat model
- [ ] Code change
- [ ] Regression test
- [ ] Security test negativo
- [ ] Backward compatibility check
- [ ] Review degli endpoint/call-site correlati

Usare questa checklist per ogni remediation.

Non considerare una finding chiusa solo perché il singolo punto di codice è stato modificato.

La finding è **DONE** quando:

```text
vulnerability fixed
+
regression test
+
negative attack test
+
related call-sites reviewed
```

---

# Security baseline già presente

Durante la review sono risultati già presenti diversi controlli importanti:

- RS256 con `kid`
- key rotation
- issuer validation
- `exp` / `iat` / `sub`
- PKCE S256
- OAuth state validation
- redirect URI validation
- authorization code single-use
- refresh token rotation
- refresh token family revocation
- refresh token reuse detection
- audience binding
- client assertion JWT
- DPoP
- CSRF protection
- HttpOnly cookies
- Secure cookies in production
- HSTS
- CSP
- `frame-ancestors 'none'`
- request size limit
- API key hashing
- API key IP allowlist
- account lockout
- AES-256-GCM PII encryption
- HMAC indexes
- encrypted JWT key material
- SSRF protection
- centralized RBAC
- audit logging
- WebAuthn generic errors
- implicit OAuth grant disabilitato

Questi controlli non vanno riscritti durante le remediation salvo che un nuovo finding dimostri un problema concreto.

---

# Definition of Done complessiva

AuthGlow può essere considerato pronto per una nuova security review quando:

- [ ] tutti i P0 sono chiusi
- [ ] tutti i P1 sono chiusi
- [ ] i test AUTH-001..018 sono implementati
- [ ] replay protection e rate limiting funzionano in multi-instance
- [ ] nessun temporary bearer secret viene persistito in plaintext
- [ ] OAuth client authentication è strict
- [ ] Passkey RP/origin è configurato esplicitamente
- [ ] SSRF protection è resistente a redirect e DNS rebinding
- [ ] admin API non espone credential material
- [ ] security CI può bloccare vulnerability High/Critical
- [ ] viene eseguito un nuovo review completo sui call-site coinvolti

## Priorità assoluta

Se bisogna procedere un finding alla volta:

```text
AUTH-001
↓
AUTH-002
↓
AUTH-003
↓
AUTH-004
↓
AUTH-005
↓
AUTH-006
↓
AUTH-007
↓
AUTH-008
↓
AUTH-009
↓
AUTH-010
↓
AUTH-011
↓
AUTH-012
```

Ogni nuova sessione dovrebbe partire indicando:

> "Security remediation AuthGlow. Implementa AUTH-XXX dal Security Remediation Plan. Prima analizza il codice attuale e i test esistenti, poi proponi il fix minimo necessario, implementalo, aggiungi regression test e verifica che non ci siano call-site correlati che mantengono la vulnerabilità."