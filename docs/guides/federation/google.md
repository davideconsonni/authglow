# Google OIDC Integration

## Overview

Google is the most widely available OIDC provider and the perfect way to test AuthGlow federation.
Once configured, users can sign in with their Google account ("Sign in with Google") alongside email/password and other providers.

AuthGlow uses the standard OIDC Authorization Code flow. No Google-specific libraries needed.

- **Google OIDC documentation**: [OpenID Connect on Google](https://developers.google.com/identity/openid-connect/openid-connect)
- **Google API Console**: [console.cloud.google.com](https://console.cloud.google.com/)

## Prerequisites

### 1. Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Go to **APIs & Services** → **Credentials**

### 2. Configure the OAuth Consent Screen

Before creating credentials, configure the consent screen:

1. Go to **APIs & Services** → **OAuth consent screen**
2. Choose **External** (unless you're using Google Workspace)
3. Fill in:
   - **App name**: your application name
   - **User support email**: your email
   - **Developer contact email**: your email
4. Click **Add or Remove Scopes** and add:
   - `openid`
   - `.../auth/userinfo.email`
   - `.../auth/userinfo.profile`
5. Click **Save and Continue**
6. Add your email as a test user (required for External type)
7. Click **Save and Continue**

### 3. Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **Create Credentials** → **OAuth client ID**
3. Choose **Web application**
4. Set **Name**: `AuthGlow`
5. Under **Authorized redirect URIs**, add:
   ```
   http://localhost:8000/api/federation/callback?provider_id=YOUR-PROVIDER-ID
   ```
   Replace `YOUR-PROVIDER-ID` with the ID you'll get after creating the provider in AuthGlow.
   
   For production, add your actual domain:
   ```
   https://your-domain.com/api/federation/callback?provider_id=YOUR-PROVIDER-ID
   ```
6. Click **Create**
7. Copy the **Client ID** and **Client Secret**

## Configuration in AuthGlow

### Via Admin UI

1. Go to **Admin** → **Federation** (`/admin/federation`)
2. Click **"Add Provider"**
3. Fill in the fields:

| Field | Value |
|---|---|
| Label | `Google` |
| Description | `Sign in with Google` |
| Issuer URL | `https://accounts.google.com` |
| Client ID | Your Google Client ID |
| Client Secret | Your Google Client Secret |
| Scopes | `openid profile email` |
| Icon URI | `https://www.google.com/favicon.ico` |

4. Click **Save**
5. The provider is created **disabled** by default — click the power icon to **enable** it

### Via API

```bash
curl -X POST http://localhost:8000/api/federation/providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "label": "Google",
    "description": "Sign in with Google",
    "issuer": "https://accounts.google.com",
    "client_id": "your-google-client-id.apps.googleusercontent.com",
    "client_secret": "GOCSPX-your-secret",
    "scopes": ["openid", "profile", "email"],
    "icon_uri": "https://www.google.com/favicon.ico"
  }'
```

### Verify Discovery

Google's OIDC discovery should return a valid configuration:

```bash
curl https://accounts.google.com/.well-known/openid-configuration | jq .
```

Expected response includes:
- `authorization_endpoint`: `https://accounts.google.com/o/oauth2/v2/auth`
- `token_endpoint`: `https://oauth2.googleapis.com/token`
- `userinfo_endpoint`: `https://openidconnect.googleapis.com/v1/userinfo`
- `issuer`: `https://accounts.google.com`

### Update Redirect URI

After creating the provider in AuthGlow, copy its **ID** from the federation table (e.g., `a1b2c3d4-...`) and add it to Google's authorized redirect URIs:

```
http://localhost:8000/api/federation/callback?provider_id=a1b2c3d4-...
```

> You can add multiple redirect URIs (development, staging, production) in Google Cloud Console.

## Authentication Flow

```
1. User lands on /auth/login or /oauth2/authorize
   → Sees "or continue with" section with the Google button

2. User clicks "Google"
   → Redirected to https://accounts.google.com/o/oauth2/v2/auth
     ?response_type=code
     &client_id=...
     &redirect_uri={authglow}/api/federation/callback?provider_id={id}
     &scope=openid+profile+email
     &state={random}
     &nonce={random}

3. User signs in with Google
   (or is already signed in → instant redirect)

4. Google redirects back to AuthGlow:
   GET /api/federation/callback?provider_id={id}&code={code}&state={state}

5. AuthGlow exchanges the code for tokens:
   POST https://oauth2.googleapis.com/token
   → receives access_token, id_token

6. AuthGlow fetches userinfo:
   GET https://openidconnect.googleapis.com/v1/userinfo
   → receives: sub, email, name, picture, email_verified

7. AuthGlow maps claims to local user:
   - sub (Google's user ID) → external_id
   - email → email
   - name → name
   - picture → picture
   → Creates or links the user account

8. AuthGlow issues its own tokens and completes the login/authorization flow
```

## Claims Mapping

Google returns these standard claims via the userinfo endpoint:

| Google Claim | AuthGlow Field | Notes |
|---|---|---|
| `sub` | `external_id` | Unique Google account identifier |
| `email` | `email` | Always verified by Google (`email_verified: true`) |
| `name` | `name` | Full display name |
| `given_name` | (in name) | First name |
| `family_name` | (in name) | Last name |
| `picture` | `picture` | Profile picture URL |
| `hd` | — | Google Workspace domain (if applicable) |

Default mapping is correct for Google — no customization needed.

## Test Users

When using the **External** consent screen type, only **test users** you explicitly add can sign in:

1. Go to **APIs & Services** → **OAuth consent screen** → **Test users**
2. Click **Add Users** and add your email
3. These are the only accounts that can authenticate until you publish the app

To go to production, click **Publish App** under the OAuth consent screen. Google requires app verification for production use.

## Important Notes

- **Default redirect URI format**: `{api_url}/api/federation/callback?provider_id={provider_id}`
  The `provider_id` query parameter is mandatory — AuthGlow uses it to identify which provider configuration to use.
- **Email is always verified**: Google guarantees `email_verified: true` — AuthGlow trusts this and marks federated user emails as verified.
- **Google does not support `offline_access` in the same way**: if you need refresh tokens from Google, add `access_type=offline` (not covered by the default OIDC flow).
- **Rate limits**: Google has quota limits. For production, monitor your usage in Google Cloud Console.

## Testing with Playground

1. Configure an OAuth client in **Admin** → **OAuth Clients** with `authorization_code` grant type
2. In the **OAuth Playground** (`/admin/playground`), select "Authorization Code Flow"
3. Enter `client_id`, `redirect_uri`, and scopes
4. At the "Authorize" step, click "Open in Browser" → the login+consent page shows the "Google" button

## References

- [Google OIDC Documentation](https://developers.google.com/identity/openid-connect/openid-connect)
- [Google Identity Platform](https://developers.google.com/identity)
- [Google API Console](https://console.cloud.google.com/)
- [OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google Branding Guidelines](https://developers.google.com/identity/branding-guidelines) — for the "Sign in with Google" button