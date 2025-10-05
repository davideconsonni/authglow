# Overview: OAuth 2.0 & OIDC in AuthGlow

AuthGlow acts as a robust Authorization Server, allowing you to secure your applications using the industry-standard OAuth 2.0 and OpenID Connect (OIDC) protocols. This guide provides a high-level overview of the available authentication flows and helps you choose the right one for your needs.

## Which Authentication Flow Should I Use?

Choosing the correct OAuth 2.0 flow is critical for security and functionality. Here’s a quick guide to the flows supported by AuthGlow:

---

### 1. Authorization Code Flow + PKCE

-   **Use Case**: The most common and secure flow. Use it for:
    -   **Traditional Web Applications**: Apps with a backend (e.g., Python/FastAPI, Node.js/Express, Java/Spring).
    -   **Single Page Applications (SPAs)**: Modern frontend apps (e.g., React, Vue, Angular) that have a backend component (Backend for Frontend).
    -   **Native Mobile/Desktop Apps**: Applications that can securely store a client secret or handle redirects.

-   **How it works**: The user is redirected to AuthGlow to log in. AuthGlow sends back an authorization `code`. Your application's backend exchanges this `code` (along with a `client_secret`) for an `ID Token` and `Access Token`. PKCE adds a layer of security that makes it safe even for public clients like mobile apps.

-   ➡️ **[Go to the detailed Web App guide & examples](./05-oauth-flow-webapp.md)**
-   ➡️ **[Go to the detailed SPA guide & examples](./06-oauth-flow-spa.md)**

---

### 2. Client Credentials Flow

-   **Use Case**: For non-interactive, machine-to-machine (M2M) communication. Use it when:
    -   A backend service needs to access a protected API on its own behalf, not on behalf of a user.
    -   You need to authorize command-line tools or scripts for internal APIs.

-   **How it works**: Your service authenticates directly with AuthGlow using its `client_id` and `client_secret`. In return, it gets an `Access Token` that is not tied to any specific user.

-   ➡️ **[Go to the detailed M2M guide & examples](./07-oauth-flow-m2m.md)**

---

## OIDC Discovery Endpoint

To simplify integration, AuthGlow provides a standard OIDC discovery endpoint. Many certified OIDC libraries can use this URL to automatically configure themselves with the correct endpoints, public keys, and supported scopes.

You can find the discovery document at:

**`http://<your-authglow-domain>/.well-known/openid-configuration`**

This endpoint provides crucial metadata, including:
- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri` (for token signature validation)
- `scopes_supported`
- and more.
