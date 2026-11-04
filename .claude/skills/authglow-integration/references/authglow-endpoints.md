# AuthGlow Endpoints and Capabilities

Authoritative-in-spirit, discovery-in-practice: always confirm against
`GET {issuer}/.well-known/openid-configuration` on the target issuer.
The table below matches the current AuthGlow source; discovery wins on
any disagreement.

## Endpoints (issuer-relative)

| Purpose | Endpoint | Notes |
| --- | --- | --- |
| Discovery | `/.well-known/openid-configuration` | Public, cacheable 1h |
| Public keys | `/.well-known/jwks.json` | Active + rotation-overlap keys only |
| Authorization | `/oauth2/authorize` | Frontend-driven page (sign-in + consent UI backed by `POST /api/oauth2/authorize`); send users here, do not collect passwords |
| Token | `/oauth2/token` | Authorization code, refresh, client credentials |
| UserInfo | `/oauth2/userinfo` | `Authorization: Bearer <access_token>` |
| Client registration | `/oauth2/register` | RFC 7591 DCR; secret returned once |
| Introspection | `/oauth2/introspect` | RFC 7662; requires client authentication |
| Revocation | `/oauth2/revoke` | RFC 7009 |
| Logout | `/oauth2/logout` | RP-initiated logout |
| Pushed requests | `/oauth2/par` | RFC 9126 |
| Device flow | `/oauth2/device/authorize` | RFC 8628 |

There is no `/api/token`. Token operations always go through `/oauth2/token`.

## Client authentication methods

As advertised by `token_endpoint_auth_methods_supported`:

- `client_secret_basic`, `client_secret_post`
- `client_secret_jwt` (HS256), `private_key_jwt` (RS256)
- `none` — public clients only, PKCE required

PKCE is S256-only. Authorization responses use `query` mode only.

## Scopes

Default `scopes_supported`: `openid profile email phone address offline_access`.
Request the minimum needed; unknown scopes are filtered unless the
client opts into strict rejection.

## API keys (non-OAuth shortcut)

For server-to-server calls where a full OAuth flow is overkill, create a
scoped API key in the admin UI and send it as:

```text
X-API-Key: ak_...
```

or

```text
Authorization: Bearer ak_...
```

Keys are bcrypt-hashed server-side and shown once at creation.

## Token lifecycle

- Access tokens are short-lived JWTs (RS256 by default).
- Refresh tokens rotate on every use; the old token must be discarded.
- Reusing an old refresh token invalidates the whole token family and
  is logged as a security event — never retry with a rotated-out token.
