# AuthGlow — Security Policy

> **Status**: maintained
> **Scope**: production security posture, threat model, supported standards.

This document is the single source of truth for **what AuthGlow does and does
not expose** to client applications. It is the reference for the
[`CONFORMANCE_REMEDIATION_PLAN.md`](plans/CONFORMANCE_REMEDIATION_PLAN.md) and
for any new OAuth/OIDC feature being added.

---

## OAuth 2.0 / OIDC Grants Supportati

AuthGlow espone un **token endpoint OAuth 2.0 standard** su
`POST /oauth2/token` che accetta **esclusivamente** i seguenti grant type:

| Grant                                           | Endpoint            | Note                                              |
|-------------------------------------------------|---------------------|---------------------------------------------------|
| `authorization_code`                            | `/oauth2/token`     | PKCE **obbligatorio** (RFC 7636) per tutti i client |
| `refresh_token`                                 | `/oauth2/token`     | Con rotazione (ogni refresh emette un nuovo RT)   |
| `client_credentials`                            | `/oauth2/token`     | Solo per client confidential, no `none`           |
| `urn:ietf:params:oauth:grant-type:device_code` | `/oauth2/token`     | RFC 8628 (Device Authorization Grant)             |

Tutti gli altri grant type — incluso **`resource_owner_password_credentials`
(ROPC, RFC 6749 §4.3)** — vengono **rifiutati esplicitamente con HTTP 400**
("Unsupported grant_type"). Vedi test di non-regressione in
`backend/tests/integration/test_token_endpoint_ropc.py`.

### Endpoint first-party (NON sono grant OAuth2)

L'endpoint `POST /api/token` accetta credenziali email+password e imposta i
cookie di sessione httpOnly. **Non è un grant OAuth2 standard** e **non deve
essere esposto a client di terze parti**. È riservato al frontend AuthGlow
stesso (Playground, dashboard).

| Endpoint     | Chi può usarlo             | Standard OAuth2? |
|--------------|----------------------------|------------------|
| `/api/token` | Solo il frontend AuthGlow  | ❌ No             |

### Perché ROPC non è supportato

ROPC è stato rimosso da OAuth 2.1 e sconsigliato dall'OAuth 2.0 Security BCP:

1. **Richiede all'app di terze parti di vedere la password utente in chiaro**:
   rompe il principio "il client non vede mai la password".
2. **Abilita phishing** mascherato da "login nativo": l'app può inviare la
   password a un server arbitrario.
3. **Impedisce MFA forte** a monte: la password deve essere presentata
   verbatim, e il client decide cosa farne.

OIDC Core 1.0 non prevede ROPC e richiede `authorization_code` + PKCE per
tutti i flussi.

---

## Standards Compliance

AuthGlow mira a essere **OIDC Core 1.0 + OAuth 2.0 Security BCP compliant**.

Vedi il piano di remediation completo per i dettagli:
[`docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`](plans/CONFORMANCE_REMEDIATION_PLAN.md).

### OAuth 2.0 / OIDC Conformance Fixes Applied (workstream A–S, T)

I seguenti fix di conformance sono stati applicati, in ordine di
workstream. Ogni riga include il riferimento al workstream e una
sintesi del comportamento. Per i dettagli implementativi vedi il
piano di remediation e la documentazione FAPI.

| Workstream | Fix                                                                             | Comportamento                                                                                          |
|------------|---------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **A**      | JWT audience validation                                                         | `aud` claim richiesto e verificato per ID Token e access token emessi su grant OAuth2. RFC 7523 §3. |
| **B**      | PKCE obbligatorio per tutti i client (RFC 7636)                                  | `Settings.enforce_pkce=True` (default). Solo `S256` (no `plain`). Ogni DCR imposta `require_pkce=True`. |
| **C**      | CSRF protection su `/oauth2/authorize` POST                                      | Token CSRF server-side richiesto se l'utente è già autenticato via cookie. `event_type="csrf_token_mismatch"`. |
| **D**      | `post_logout_redirect_uri` strict validation                                     | Confronto strict con `allowed_post_logout_redirect_uris`. `oidc_strict_logout_redirect=True` (default). |
| **E**      | Rimozione `implicit` grant                                                       | Discovery e DCR rifiutano `implicit` (RFC 6749 §10.16, OAuth 2.0 Security BCP).                |
| **F**      | Claim `amr` e `acr` su ID Token (OIDC Core §2)                                  | Mapping statico in `services/acr.py`. `compute_acr` basato sui metodi auth usati.               |
| **G**      | OIDC `prompt` parameter (`none`, `login`, `consent`, `select_account`)            | `authorize_post` e `oauth2_mfa_verify` gestiscono la matrice di valori. RFC 6819 §5.2.         |
| **H**      | OIDC `max_age` parameter                                                         | Se `auth_time` è più vecchio di `max_age`, forza re-auth.                                            |
| **I**      | OIDC `id_token_hint` login                                                        | Pre-popola `email` se l'ID Token è valido.                                                            |
| **J**      | Token blacklist persistente                                                     | File-based (multi-instance visibility). RFC 7009.                                                   |
| **K**      | RFC 7592 DCR Management (GET/PUT/DELETE `/oauth2/register/{id}`)                  | HTTP Basic auth obbligatoria.                                                                        |
| **L**      | OIDC Front-/Back-Channel Logout                                                   | `frontchannel_logout_supported=true`. `sid` claim su ID Token. Back-channel deferred.            |
| **M**      | `at_hash` / `c_hash` claim su ID Token (OIDC Core §3.1.3.6 / §3.3.2.11)         | Left-half SHA-256 base64url, no padding.                                                              |
| **N**      | UserInfo cleanup                                                                 | Rimosso claim `permissions` custom. `address` claim opzionale (RFC 5646).                         |
| **O**      | Rate limiting su endpoint OIDC core                                              | `60/minute` discovery/JWKS, `120/minute` userinfo, `30/minute` logout.                             |
| **P**      | DCR hardening                                                                    | `none`+`client_credentials` rifiutato, URI metadata HTTPS-only, `software_statement` validato JWT.  |
| **Q**      | `state` parameter validation (RFC 6819 §4.4.1.8)                                 | `state` persisted on `AuthorizationCode`, warning loggato se assente.                              |
| **R**      | JWKS Status endpoint                                                             | `GET /oauth2/jwks/status` pubblico, con `status` per ogni kid. RFC 7517.                         |
| **S**      | Device Authorization Grant (RFC 8628)                                           | `device_authorization_endpoint`, `device_code` + `user_code` + verification URI.                  |
| **T.2**    | Client JWT auth (`client_secret_jwt` HS256, `private_key_jwt` RS256)             | RFC 7521 / 7523. Standard OIDC Core §9. FAPI 2.0 §5.2.1.                                          |
| **T.3**    | DPoP-bound tokens (RFC 9449)                                                     | ES256 only. `cnf.jkt` claim. UserInfo verifica proof. JTI replay protection.                     |
| **T.4**    | FAPI 2.0 gap analysis                                                            | Documento `docs/FAPI.md` con piano per colmare i gap rimanenti (PAR, mTLS, JARM).                  |

### Gap rimanenti (workstream T continuazione)

Vedi [`docs/FAPI.md`](FAPI.md) per il piano dettagliato:

- **PAR (RFC 9126) — P1**: Pushed Authorization Requests, raccomandato per FAPI 2.0 "Read and Write".
- **JARM (RFC 9396) — P2**: JWT-secured Authorization Response, opzionale.
- **mTLS (RFC 8705) — P2**: certificati client per client authentication e token binding.
- **Code lifetime ≤ 30s — P2 (config-only)**: già configurabile, default 10 minuti. Per FAPI stretto: `OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5`.

### Compliance Test Plan

I test di conformità end-to-end vivono in
[`docs/CONFORMANCE_TEST_PLAN.md`](CONFORMANCE_TEST_PLAN.md) e sono
esercitati dalle suite `tests/integration/test_dcr_*.py`,
`tests/integration/test_token_endpoint_*.py`,
`tests/integration/test_userinfo_*.py`. Ogni workstream che
introduce nuova funzionalità include test di integrazione che
esercitano il path completo via FastAPI TestClient.

### FAPI 2.0 — Quick-Start Configuration

Per deploy in modalità FAPI 2.0 "Read-Only" oggi:

```bash
# .env
OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5
ENFORCE_PKCE=true
DPOP_SIGNING_ALG_VALUES_SUPPORTED=ES256
```

Per-client (admin UI):
- `token_endpoint_auth_method` = `private_key_jwt` (raccomandato) o `client_secret_jwt`
- `dpop_bound` = `true` (raccomandato)
- `public_jwk` valorizzato per `private_key_jwt`
- `redirect_uris` HTTPS, no wildcards

Vedi [`docs/FAPI.md`](FAPI.md) per il dettaglio.
