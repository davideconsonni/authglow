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
