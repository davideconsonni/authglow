# Client Authentication Methods

How a client authenticates to the token endpoint (and the
revocation/introspection/DCR endpoints).

---

## Standard

- **Client Metadata** — RFC 7591 §2 (`token_endpoint_auth_method`)
- **JWT Profile for OAuth 2.0 Client Auth** — RFC 7523
- FAPI 2.0 (§5.2.2) for JWT methods

---

## Supported methods

| Method | Alg | Description | Notes |
|--------|-----|-------------|-------|
| `client_secret_basic` | — | HTTP Basic. | Legacy default. |
| `client_secret_post` | — | Secret in the form body. | |
| `client_secret_jwt` | HS256 | `client_assertion` JWT signed with a symmetric key. | Key **server-minted** per client, shown once, never persisted in cleartext. |
| `private_key_jwt` | RS256 | `client_assertion` JWT signed with a private key. | Public JWK registered at DCR (`public_jwk`). |
| `none` | — | Public clients. | PKCE mandatory. |

### `client_secret_jwt` / `private_key_jwt` — details (RFC 7523)

`client_assertion` JWT with:
- `iss`, `sub` = `client_id`
- `aud` = the token endpoint URL
- `exp`, `jti` (single-use, replay-protected)

The server verifies the signature (HS256 with the encrypted server-side
key, or RS256 with the public JWK) in `services/client_jwt_auth.py`.
For `client_secret_jwt` the key is minted by the server at client creation
and shown once; the plaintext is never persisted, only a Fernet-encrypted
copy is stored on disk.

---

## How we use it

On the token endpoint (with form or HTTP Basic), and we accept
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
as a stronger alternative to the secret for `client_credentials` and
`authorization_code`.

---

## Conformance

| Aspect | Status |
|--------|--------|
| RFC 7591 §2 | Full support for the declared methods. |
| RFC 7523 | Conformant (HS256/RS256). |
| `client_secret_jwt` key | **Custom**: minted by the server (never received client-side over the wire). |
| `public_jwk` | Embedded at DCR (no JWKS round-trip). |
| `none` | Public clients only; PKCE mandatory. |

---

## Endpoints

| Method | Path | Role |
|--------|------|------|
| POST | `/oauth2/token` | Applies the client's registered method |
| POST | `/oauth2/revoke` | Client auth for RFC 7009 |
| POST | `/oauth2/introspect` | Client auth for RFC 7662 |

---

> **Custom vs standard**: essentially conformant. Differences: the
> `client_secret_jwt` key is server-minted (safer — the secret is shown
> once), and the public JWK is embedded at DCR instead of a JWKS fetch.