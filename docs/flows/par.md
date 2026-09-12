# Pushed Authorization Requests (PAR)

Clients push authorization parameters to the server over an
authenticated backchannel and receive a short-lived single-use
`request_uri`. The browser then carries only `client_id` +
`request_uri` instead of the full parameter set (OA-501).

---

## Standard

- **Pushed Authorization Request Endpoint** — RFC 9126
- Required building block of the FAPI 2.0 Security Profile

---

## Actors

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (RP)
    participant P as AuthGlow PAR Endpoint
    participant B as Browser
    participant A as AuthGlow Authorize

    C-->>P: POST /oauth2/par (client auth + authorize params)
    P-->>C: 201 {request_uri, expires_in}
    C->>B: redirect with client_id + request_uri
    B->>A: authorize (request_uri only)
    A->>A: resolve + single-use consume + bind to client
    U->>A: log in + consent (unchanged)
    A-->>C: 302 redirect_uri?code=...&state=...
```

---

## How we support it

### 1. Push (backchannel, authenticated)

```
POST /oauth2/par   (form URL-encoded)
```

Auth like the token endpoint (`client_secret_basic`,
`client_secret_post`, `client_secret_jwt`, `private_key_jwt`;
public clients with `client_id` only). Same validations as
authorize (redirect exact-match, PKCE, grant, scopes).

```
201 { "request_uri": "urn:ietf:params:oauth:request_uri:<opaque>",
      "expires_in": 90 }
```

TTL 90s (`par_request_uri_ttl_seconds`), single-use, bound to the
pushing client. Errors are direct RFC 6749 §5.2 bodies (no
redirect — the client has not been sent anywhere yet).

### 2. Authorize with `request_uri`

```
POST /api/oauth2/authorize   (form)   client_id + request_uri
```

The stored parameters replace the front-channel ones
(`scope`, `state`, PKCE, `nonce`, `prompt`, `max_age`, `claims`).
Unknown/expired/used/foreign `request_uri` → 302
`error=invalid_request`. Clients flagged `require_par` that call
without `request_uri` → 302 `error=invalid_request`.

---

## Conformance

| Aspect | Status |
|--------|--------|
| `request_uri` format | `urn:ietf:params:oauth:request_uri:` + opaque id (RFC 9126 §2.2) |
| TTL | 90s default, configurable |
| Single-use | consume-on-first-presentation (CAS + lock) |
| Client binding | stored `client_id` must match the presenter |
| `require_par` | Opt-in per client (default off — tightening only) |
| Discovery | `pushed_authorization_request_endpoint` advertised |

---

## Endpoints

| Method | Path | Role |
|--------|------|------|
| POST | `/oauth2/par` | Push params, get `request_uri` (201) |

---

> **Custom vs standard**: `require_par` is our FAPI opt-in flag;
> everything else follows RFC 9126. The token endpoint never sees
> `request_uri` — it only ever redeems `code` as before.
