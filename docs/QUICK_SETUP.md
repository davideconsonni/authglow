# Quick Setup Guide

How to get AuthGlow running — from zero to signed in — in under 5 minutes.

---

## Local Development

Two terminals. Full experience (API + UI).

### Terminal 1 — Backend

```bash
git clone https://github.com/davideconsonni/authglow.git
cd authglow/backend

python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Open .env and set a SECRET_KEY (32+ random chars):
#   python -c "import secrets; print(secrets.token_urlsafe(48))"

python main.py
```

API live at **http://localhost:8000** (Swagger UI at [`/docs`](http://localhost:8000/docs)).
Watch the console for a line containing `setup_token_generated` — copy the `token` value.

### Terminal 2 — Frontend

```bash
cd authglow/frontend
cp .env.example .env
# Change VITE_API_URL to http://localhost:8000

npm install && npm run dev
```

Open **http://localhost:5173/setup**, paste the setup token, create your admin account. Sign in normally from `/auth/login`.

---

## Deployed / Remote Instance

If you've deployed AuthGlow (Render, Fly.io, Cloud Run, etc.) and are starting with an empty instance,
here's the minimal flow to create the first user and get a working API token.

### 1. Check if setup is needed

```bash
curl -s https://your-instance.example.com/api/setup/check
```

Expected response when setup is needed:

```json
{"needs_setup": true, "message": "Initial setup required"}
```

If you get `"needs_setup": false`, there are already users — skip to step 4.

### 2. Get the setup token

The setup token is a one-time secret generated automatically on first boot,
or pre-set via the `SETUP_TOKEN` environment variable.

**If you set `SETUP_TOKEN`** in your environment: use that value.

**If it was auto-generated** (you didn't set `SETUP_TOKEN`): check your platform's logs.
Search for `setup_token_generated` — you'll see an entry like:

```
setup_token_generated  token="VRaZSnTRCGPDr-630K7NxazJ0ICsN1Cqei8ZKYGxWq4"
```

| Platform | Where to find logs |
|---|---|
| Render | Dashboard → service → **Logs** tab |
| Fly.io | `fly logs` in terminal |
| Cloud Run | Cloud Console → Cloud Run → service → **Logs** |
| Railway | Dashboard → service → **Deployments** → view logs |
| Heroku | `heroku logs -t` in terminal |

If you can't find the log line (logs may have rotated), redeploy or restart the service
and watch live logs — the token is printed on every startup while no users exist.

### 3. Create the admin account

Use the setup token as a Bearer token:

```bash
curl -s -X POST https://your-instance.example.com/api/setup/create-admin \
  -H "Authorization: Bearer YOUR_SETUP_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePwd1!",
    "first_name": "Admin",
    "last_name": "User"
  }'
```

**Password requirements** (default policy):
- At least 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (!@#$%^&*...)

Success response:

```json
{
  "message": "Administrator account created successfully",
  "user_id": "536a00f2-2998-4d47-a35d-220a5995fa6e",
  "email": "admin@example.com"
}
```

**After this call succeeds, the setup token is consumed.** Subsequent calls return `404`.

### 4. Log in through OAuth2/OIDC

Open the frontend and choose **Sign in with AuthGlow**. The dashboard uses
Authorization Code + PKCE and creates httpOnly browser session cookies after
the callback. Third-party applications must register their own OAuth client
and use the standard `/oauth2/authorize` and `/oauth2/token` endpoints.

Response:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "wMj934sR6A...",
  "scope": "read write admin",
  "id_token": null,
  "password_expired": false
}
```

### 5. Call a protected endpoint

```bash
curl -s https://your-instance.example.com/api/users/me \
  -H "Cookie: access_token=YOUR_ACCESS_TOKEN"
```

Response:

```json
{
  "id": "536a00f2-...",
  "email": "admin@example.com",
  "is_active": true,
  "scopes": ["read", "write", "admin"],
  "mfa_enabled": false,
  "email_verified": true,
  ...
}
```

### 6. Using Swagger UI

Open `https://your-instance.example.com/docs` in a browser:

1. Use the dashboard login or a registered OAuth2/OIDC client.
2. For API testing, send a valid Bearer access token issued by `/oauth2/token`.
3. The lock icon appears on protected endpoints.

### Token refresh

Access tokens expire after 30 minutes (configurable via `ACCESS_TOKEN_EXPIRE_MINUTES`).
To refresh without re-entering credentials:

The dashboard refreshes its httpOnly cookie session with
`POST /api/auth/refresh`. External OAuth2 clients rotate refresh tokens using
`POST /oauth2/token` with `grant_type=refresh_token`.

---

## Troubleshooting

| Problem | Likely Cause | Fix |
|---|---|---|
| `403` on `/api/setup/create-admin` | Wrong or missing setup token | Verify token from logs or `SETUP_TOKEN` env var |
| `404` on `/api/setup/create-admin` | Setup already completed | Users exist — use the dashboard OAuth2 login |
| `500` on `/api/setup/create-admin` | `SETUP_TOKEN` not configured on server and auto-generation failed | Check server config, redeploy |
| `400` "Password validation failed" | Password doesn't meet policy | Use a password with uppercase, lowercase, digit, special char, 8+ chars |
| `401` on `/oauth2/authorize` | Invalid credentials or inactive user | Check the account status and retry |
| `423` on `/oauth2/authorize` | Account locked | Too many failed attempts — wait or unlock via admin |
| `401` on protected endpoints | Token expired (30 min default) | Refresh the token or log in again |
| Swagger can't reach API | CORS or `BASE_URL` mismatch | Set `BASE_URL` to your public URL; add frontend URL to `CORS_ALLOWED_ORIGINS` |

---

## Next Steps

- Register more users at `POST /api/users` (requires `allow_public_registration=true`)
- Create OAuth2 clients at `POST /api/admin/clients` for third-party integrations
- Set up passkeys at `POST /api/passkeys/register/begin`
- Explore every OAuth2 flow with the built-in OAuth Playground (`/playground` in the frontend)
- Full feature list: [FEATURES.md](FEATURES.md)
