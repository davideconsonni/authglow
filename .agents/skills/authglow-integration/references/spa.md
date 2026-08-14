# SPA and Browser Integration

Use Authorization Code + PKCE with a public client. Prefer a backend-for-frontend when the application has a server component; otherwise keep short-lived tokens in memory and use a secure refresh strategy supplied by the application architecture.

## Configuration

Typical public configuration:

```text
AUTHGLOW_ISSUER=https://auth.example.com
AUTHGLOW_CLIENT_ID=...
AUTHGLOW_REDIRECT_URI=https://app.example.com/auth/callback
AUTHGLOW_POST_LOGOUT_REDIRECT_URI=https://app.example.com/
```

Only the issuer, client ID, and public redirect URI may be exposed to browser code. Never expose a client secret.

## Required behavior

- Generate state, nonce, and verifier with Web Crypto.
- Store transaction data in memory or session-scoped storage with a strict expiry; never store tokens there.
- Validate callback state before exchanging the code.
- Validate the ID token nonce and claims.
- Use the host framework's router for internal redirects.
- Do not call `/api/token`; it is not registered. Use Authorization Code + PKCE through discovery.

## Preferred libraries

Use a maintained OIDC client for the chosen framework when one exists. If a tiny wrapper is needed, it should expose `login`, `handleCallback`, `getUser`, `logout`, and `isAuthenticated`, while delegating cryptography and protocol details to the library.
