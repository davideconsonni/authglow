# AuthGlow Protocol Contract

This reference describes the integration contract, not a replacement for live discovery. The active issuer metadata and current AuthGlow source win when they differ.

## Discovery

Start with:

```text
GET {issuer}/.well-known/openid-configuration
```

Use the returned endpoint URLs. Do not hardcode `/oauth2/token`, `/oauth2/userinfo`, or `/oauth2/logout` when discovery is available.

## Authorization Code + PKCE

Authorization request requirements for public clients:

```text
response_type=code
client_id=...
redirect_uri=exact-registered-uri
scope=openid profile email
state=fresh-csprng-value
nonce=fresh-csprng-value
code_challenge=base64url(sha256(code_verifier))
code_challenge_method=S256
```

Callback processing order:

1. Confirm the callback URL belongs to the expected registered redirect URI.
2. Read `error` and stop with a user-safe error if present.
3. Require and compare `state` with the transaction value.
4. Require the authorization `code`.
5. Exchange the code once with the original `redirect_uri` and `code_verifier`.
6. Validate the ID token before using claims.
7. Delete the one-time transaction data.

## ID token validation

When `openid` is requested, validate:

- signature using the issuer JWKS;
- `iss` equals discovered issuer;
- `aud` contains the client ID;
- `exp` and `iat` are valid;
- `nonce` equals the transaction nonce;
- `azp` when required by the audience shape.

Do not treat a decoded but unsigned JWT as trusted.

## Access token and UserInfo

Use the access token only for the intended resource server. For UserInfo:

```text
Authorization: Bearer {access_token}
```

The resource server must enforce issuer, audience, expiry, signature, and required scopes. Do not infer authorization from email or frontend state.

## Refresh and logout

- Keep refresh tokens server-side or in platform secure storage.
- Expect refresh-token rotation and discard the old token after success.
- Handle refresh-token reuse as a security event.
- Use `end_session_endpoint` for OIDC RP-initiated logout.
- Validate `post_logout_redirect_uri` against the registered client configuration.

## First-party distinction

`/api/token` is AuthGlow's internal browser login endpoint. It is not the integration API for third-party clients and must not be presented as an OAuth2 password grant.
