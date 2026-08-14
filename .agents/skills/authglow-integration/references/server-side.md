# Server-Side Web Integration

Use a confidential client and Authorization Code Flow. The browser receives an application session cookie; AuthGlow tokens remain on the server.

## Configuration

```text
AUTHGLOW_ISSUER=https://auth.example.com
AUTHGLOW_CLIENT_ID=...
AUTHGLOW_CLIENT_SECRET=server-secret-store-reference
AUTHGLOW_REDIRECT_URI=https://app.example.com/auth/callback
```

Load the secret from the platform secret manager. Do not commit it or render it into HTML.

## Required routes

- `/login`: create state, nonce, and PKCE transaction as appropriate.
- `/auth/callback`: validate callback, exchange code, validate ID token, create local session.
- `/logout`: clear local session and invoke OIDC logout when configured.
- protected routes: require the local session.

Use the application session as the browser boundary. Do not forward refresh tokens to templates or JavaScript.
