# Guide: Using AuthGlow as an OAuth 2.0 / OIDC Provider

This is a comprehensive guide to integrating your application with AuthGlow using the OAuth 2.0 and OpenID Connect (OIDC) standards. AuthGlow acts as a centralized Authorization Server, allowing your users to log in securely without your application ever handling their passwords directly.

AuthGlow implements the **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**. This is the most secure and recommended flow for both web applications and native/mobile apps.

## Core Concepts

-   **Authorization Server**: This is AuthGlow. It manages users and grants access tokens.
-   **Client Application**: This is your application (e.g., a React SPA, a Python web app, a mobile app) that wants to authenticate users.
-   **Resource Owner**: The end-user who is granting permission for your application to access their information.
-   **ID Token**: A JWT (JSON Web Token) provided by AuthGlow (as an OIDC provider). It proves the user's identity and contains basic profile information (`name`, `email`, etc.).
-   **Access Token**: An opaque token (or JWT) that your application can use to access protected APIs on behalf of the user.

---

## Step 1: Create an OAuth Client in AuthGlow

Before you can start the authentication flow, you must register your application in AuthGlow's admin panel.

1.  Log in to AuthGlow as an administrator.
2.  Navigate to **OAuth Clients** from the side menu.
3.  Click **"Create New Client"**.
4.  Fill in the required information:
    *   **Client Name**: A friendly name for your application (e.g., "My Awesome App").
    *   **Redirect URIs**: This is a critical security feature. Provide a list of **absolute URLs** that AuthGlow is allowed to redirect the user back to after they log in. For local development, this is often `http://localhost:3000/callback`. **AuthGlow will refuse to redirect to any URL not on this list.**

5.  After creation, you will be provided with a **Client ID** and a **Client Secret**.
    *   **Client ID**: A public identifier for your application.
    *   **Client Secret**: A confidential key. **Treat this like a password.** It is used by your application's backend to securely exchange the authorization code for tokens.

---

## Step 2: The Authentication Flow

Here is a step-by-step breakdown of the Authorization Code Flow with PKCE.

### Part 1: Generate a Code Verifier and Challenge (Client-Side)

In your application, before redirecting the user, you must generate two values:

1.  **Code Verifier**: A high-entropy random string.
2.  **Code Challenge**: A Base64-URL-encoded SHA256 hash of the `code_verifier`.

Store the `code_verifier` in the user's session (e.g., in a cookie or session storage), as you will need it later.

**Example in Python:**
```python
import hashlib
import base64
import os

# 1. Generate a random string
code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode('utf-8')
code_verifier = code_verifier.rstrip('=')

# 2. Hash it and base64-encode it
sha256 = hashlib.sha256(code_verifier.encode('utf-8')).digest()
code_challenge = base64.urlsafe_b64encode(sha256).decode('utf-8')
code_challenge = code_challenge.rstrip('=')

# Store code_verifier in the user's session now!
```

### Part 2: Redirect the User to AuthGlow (Client-Side)

Construct a URL to AuthGlow's `/authorize` endpoint and redirect the user's browser to it.

**Base URL:** `http://<your-authglow-domain>/oauth/authorize`

**Query Parameters:**

| Parameter | Description | Example Value |
| --- | --- | --- |
| `response_type` | Must be `code`. | `code` |
| `client_id` | The Client ID you received in Step 1. | `your-client-id` |
| `redirect_uri` | The URL AuthGlow should redirect to after login. **Must match one of the registered URIs.** | `http://localhost:3000/callback` |
| `scope` | A space-separated list of permissions. Use `openid profile email` for OIDC. | `openid profile email` |
| `state` | A random string you generate to prevent CSRF attacks. Store it in the session and verify it later. | `random-string-123` |
| `code_challenge` | The value you generated in Part 1. | (The generated challenge) |
| `code_challenge_method`| Must be `S256`. | `S256` |

**Example Redirect URL:**
```
http://localhost:8000/oauth/authorize?response_type=code&client_id=my-client&redirect_uri=http://localhost:3000/callback&scope=openid%20profile%20email&state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

The user will now see the AuthGlow login page. If they are not logged in, they will be prompted to do so. Then, they will be asked to grant consent for your application to access the requested scopes.

### Part 3: Handle the Callback (Server-Side)

After the user authenticates and gives consent, AuthGlow redirects them back to your `redirect_uri` with an **authorization code** and the **state**.

**Example Callback URL:**
`http://localhost:3000/callback?code=def50200...&state=xyz`

Your application's backend should now:
1.  **Verify the `state` parameter**: Ensure it matches the value you stored in the session to prevent CSRF attacks.
2.  **Exchange the `code` for tokens**: Make a `POST` request from your backend to AuthGlow's `/token` endpoint.

### Part 4: Exchange Code for Tokens (Server-Side)

This request must be made from your server, as it includes your Client Secret.

**Endpoint:** `POST http://<your-authglow-domain>/oauth/token`
**Content-Type:** `application/x-www-form-urlencoded`

**Request Body Parameters:**

| Parameter | Description | Example Value |
| --- | --- | --- |
| `grant_type` | Must be `authorization_code`. | `authorization_code` |
| `code` | The authorization code received in the callback. | (The code from the URL) |
| `redirect_uri` | The same `redirect_uri` used in the initial request. | `http://localhost:3000/callback` |
| `client_id` | Your application's Client ID. | `your-client-id` |
| `client_secret` | Your application's Client Secret. | `your-client-secret` |
| `code_verifier` | The **original** random string you generated in Part 1 and stored in the session. | (The stored verifier) |

**Example using `curl`:**
```bash
curl -X POST http://localhost:8000/oauth/token \
  -d grant_type=authorization_code \
  -d code=... \
  -d redirect_uri=http://localhost:3000/callback \
  -d client_id=... \
  -d client_secret=... \
  -d code_verifier=...
```

### Part 5: Receive and Use the Tokens

If the request is successful, AuthGlow will respond with a JSON payload containing the tokens:

```json
{
  "access_token": "eyJ...",
  "id_token": "eyJ...",
  "refresh_token": "a_long_opaque_string...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "scope": "openid profile email"
}
```

-   **`id_token`**: You should **validate** this JWT's signature, issuer (`iss`), and audience (`aud`). Once validated, you can decode it to get user information (like `sub`, `name`, `email`). This confirms the user's identity.
-   **`access_token`**: Use this token in the `Authorization` header (`Bearer <access_token>`) to make requests to protected APIs.
-   **`refresh_token`**: Store this token securely. When the `access_token` expires, you can use the refresh token to get a new one without requiring the user to log in again.

---

## Step 3: Refreshing an Access Token

When an access token expires, use the refresh token to get a new one by making a `POST` request to the `/token` endpoint.

**Request Body Parameters:**

| Parameter | Description | Example Value |
| --- | --- | --- |
| `grant_type` | Must be `refresh_token`. | `refresh_token` |
| `refresh_token` | The refresh token you received previously. | (The stored refresh token) |
| `client_id` | Your application's Client ID. | `your-client-id` |
| `client_secret` | Your application's Client Secret. | `your-client-secret` |

---

## OIDC Discovery Endpoint

AuthGlow exposes an OIDC discovery document, which allows OIDC-compliant libraries to automatically configure themselves. This document contains all the necessary endpoint URLs and public keys.

You can find it at:
`http://<your-authglow-domain>/.well-known/openid-configuration`

