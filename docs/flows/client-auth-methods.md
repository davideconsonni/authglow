# Client Authentication Methods

Come un client si autentica al token endpoint (e agli endpoint di
revocation/introspection/DCR).

---

## Standard

- **Client Metadata** — RFC 7591 §2 (`token_endpoint_auth_method`)
- **JWT Profile for OAuth 2.0 Client Auth** — RFC 7523
- FAPI 2.0 (§5.2.2) per i metodi JWT

---

## Metodi supportati

| Method | Algo | Descrizione | Note |
|--------|------|-------------|------|
| `client_secret_basic` | — | HTTP Basic. | Default legacy. |
| `client_secret_post` | — | Secret nel form. | |
| `client_secret_jwt` | HS256 | `client_assertion` JWT firmato con chiave simmetrica. | Chiave **server-minted** per client, mostra una volta, mai persistita in chiaro. |
| `private_key_jwt` | RS256 | `client_assertion` JWT firmato con chiave privata. | JWK pubblica registrata a DCR (`public_jwk`). |
| `none` | — | Client pubblici. | PKCE obbligatoria. |

### `client_secret_jwt` / `private_key_jwt` — dettagli (RFC 7523)

`client_assertion` JWT con:
- `iss`, `sub` = `client_id`
- `aud` = URL del token endpoint
- `exp`, `jti` (monouso, replay-protected)

Il server verifica la firma (HS256 con la chiave crittografata server-side,
o RS256 con la JWK pubblica) in `services/client_jwt_auth.py`.

---

## Come lo usiamo

Sul token endpoint, sia con form che con HTTP Basic, e accettiamo
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
come alternativa forte al secret per `client_credentials` e
`authorization_code`.

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| RFC 7591 §2 | Supporto completo dei metodi dichiarati. |
| RFC 7523 | Conforme (HS256/RS256). |
| Chiave client_secret_jwt | **Custom**: minted dal server (mai ricevuta dal client over the wire). |
| JWK privata | `public_jwk` incorporata a DCR (no round-trip JWKS fetch). |
| `none` | Solo client pubblici; PKCE obbligatoria. |

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/oauth2/token` | Applica il metodo del client registrato |
| POST | `/oauth2/revoke` | Client auth su ≤RFC 7009 |
| POST | `/oauth2/introspect` | Client auth su RFC 7662 |

---

> **Custom vs standard**: sostanzialmente conforme. Le differenze: la
> chiave `client_secret_jwt` è mintata lato server (più sicura, il plaintext
> mono-volta), e la JWK pubblica incorporata a DCR invece di un JWKS fetch.