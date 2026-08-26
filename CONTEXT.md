# AuthGlow

AuthGlow è un CIAM self-hostable e un provider OAuth2/OIDC. Questo documento è il glossario
del linguaggio condiviso del progetto: i termini qui sotto hanno UN significato canonico nel
codice, nelle API e nelle discussioni. Se un termine non c'è, non è ancora stato deciso.

## Language

### Identity & Access

**User**:
La persona fisica registrata che si autentica. Ha credenziali proprie (password, passkey,
MFA) e una email verificata.
_Avoid_: account, customer, principal

**Client**:
Un'applicazione registrata presso AuthGlow che fa partire flussi OAuth2/OIDC per conto dei
suoi utenti o accede via API key.
_Avoid_: app, consumer, relying party (RP solo nel contesto OIDC documentale)

**API Key**:
Credenziale macchina-to-machine con prefisso pubblico `ak_`, legata a uno User, con tier
e allowlist IP opzionali.

**Session**:
Una connessione autenticata attiva di uno User (refresh token + cookie di accesso).
Rivolgersi alle Session quando si parla di "logout ovunque".
_Avoid_: login (il login è l'atto, non la sessione)

### Webhooks (iniziativa B)

**Webhook Endpoint**:
Un URL HTTPS registrato dall'admin che riceve eventi firmati dell'IdP. Identificato da
`wh_…`; il Signing Secret è rivelato una sola volta alla creazione.
_Avoid_: subscription, event sink, listener

**Event Catalog**:
Il catalogo chiuso dei tipi di evento emettibili, definito come costanti nel codice.
Un tipo fuori catalogo non può essere né sottoscritto né emesso.
_Avoid_: event list, topic

**Event Type**:
Un singolo tipo di evento del catalogo (es. `user.created`, `login.failed`).

**Signing Secret**:
Secret generato dal server (`whsec_…`) con cui ogni consegna viene firmata HMAC. Rivelato
una sola volta; ruotabile immediatamente; conservato cifrato a riposo.
_Avoid_: api key, token

**URL Policy**:
Regola di registrazione degli URL: HTTPS sempre; HTTP consentito solo per
localhost / 127.0.0.1 / ::1 (loopback di sviluppo). Una sola validazione URI
per tutto il progetto (`_validate_redirect_uri`).
