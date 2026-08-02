# AuthGlow — Supported Flows

Questa directory documenta ogni flusso di autenticazione/autorizzazione
supportato da AuthGlow, **come** è implementato, lo **standard** di
riferimento e — dove presente — le **differenze/custom** rispetto allo
standard.

Ogni file segue lo stesso schema:

| Sezione            | Contenuto |
|--------------------|-----------|
| **Standard**       | La RFC / spec di riferimento. |
| **Come lo supportiamo** | Endpoint coinvolti, sequenza richieste/risposte, parametri. |
| **Conformità**     | Cosa è pienamente standard, cosa è più severo, cosa è custom. |
| **Endpoint coinvolti** | Tabella endpoint (metodo + path). |

## Indice dei flussi

| Flusso | File | Standard | Principale differenza rispetto allo standard |
|--------|------|----------|----------------------------------------------|
| Authorization Code + PKCE | [`authorization-code-pkce.md`](authorization-code-pkce.md) | RFC 6749 §4.1, RFC 7636 | PKCE **obbligatorio** per TUTTI i client (anche confidential), solo `S256` |
| Client Credentials | [`client-credentials.md`](client-credentials.md) | RFC 6749 §4.4 | Scope strettamente validati (nessun scope non consentito) |
| Refresh Token Rotation | [`refresh-token-rotation.md`](refresh-token-rotation.md) | RFC 6749 §6, OAuth BCP | Rotazione automatica + **rilevamento riuso** (revoca famiglia) |
| Device Authorization Grant | [`device-authorization.md`](device-authorization.md) | RFC 8628 | Serve auth utente autenticata; polling rate-limited, `slow_down` |
| First-party browser login | [`first-party-browser-login.md`](first-party-browser-login.md) | — (NON è OAuth2) | Endpoint `/api/token` custom, cookie httpOnly, riservato al frontend |
| Revocation / Introspection | [`revocation-introspection.md`](revocation-introspection.md) | RFC 7009, RFC 7662 | Conformi; revoca access token tramite jti-blacklist |
| OIDC UserInfo | [`oidc-userinfo.md`](oidc-userinfo.md) | OIDC Core §5.1 | Supporta il `claims` request parameter (§5.5) |
| OIDC RP-Initiated Logout | [`oidc-logout.md`](oidc-logout.md) | OIDC RP-Initiated Logout 1.0 | `id_token_hint` richiesto per il redirect; front-channel via iframe |

## Meccanismi trasversali

| Meccanismo | File | Standard |
|-----------|------|----------|
| Client authentication methods | [`client-auth-methods.md`](client-auth-methods.md) | RFC 7591 §2, RFC 7523 |
| DPoP (sender-constrained tokens) | [`dpop.md`](dpop.md) | RFC 9449 |

## Convenzioni comuni (vale per tutti i flow)

- **UTC** ovunque, nessun datetime naive.
- **UTC** storage: access token JWT (lifetime per-client), refresh token con rotazione, autorization code con exp.
- **Rate limiting** per IP (o per token) su ogni endpoint di flusso.
- **Audit logging** strutturato (structlog) su ogni evento di consenso/revoca/token.
- Gli endpoint pubblici puntano a `request` con rate limit implicit.

---

> Riferimento principale: [`docs/FEATURES.md`](../FEATURES.md) — catalogo completo di endpoint e feature.