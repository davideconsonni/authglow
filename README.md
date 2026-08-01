# AuthGlow

> Self-hosted OAuth 2.0 / OpenID Connect authorization server with no database. Files in, JWTs out — swap storage backends with one environment variable.

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11+-blue.svg">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg">
  <a href="https://github.com/davideconsonni/authglow/actions/workflows/test.yml"><img alt="Test Suite" src="https://github.com/davideconsonni/authglow/actions/workflows/test.yml/badge.svg"></a>
  <img alt="AI Generated" src="https://img.shields.io/badge/AI%20Generated-100%25-blueviolet.svg">
</p>

---

## What is AuthGlow?

AuthGlow is a self-hosted **OAuth 2.0 / OpenID Connect authorization server**, user directory, and admin console — with no database to run, patch, or back up. Users, sessions, tokens, and OAuth2 clients are stored as files through an [fsspec](https://filesystem-spec.readthedocs.io/) abstraction, so the exact same code runs on your laptop, in a single Cloud Run container, or against an S3 bucket.

If you've ever looked at Keycloak or Ory Hydra and thought *"I don't want to operate a database cluster just to handle login,"* this is built for that exact moment.

Change `STORAGE_BACKEND` from `file` to `s3`, `gcs`, or `abfs` and your data — including the JWT signing keys — moves with it. No migrations, no schema, no code changes.

---

## ✨ Features

**Authentication & protocols**
- **OAuth 2.0 & OpenID Connect** — Authorization Code + PKCE, Client Credentials, Refresh Token rotation with theft detection, Token Introspection (RFC 7662), Revocation (RFC 7009), RP-Initiated Logout
- **Device Authorization Grant** (RFC 8628) — sign in on a CLI, smart TV, or IoT device by entering a code on your phone
- **Passkeys (WebAuthn/FIDO2)** — passwordless sign-in with Touch ID, Windows Hello, or a security key
- **Multi-Factor Authentication** — TOTP, backup codes, "remember this device"
- **API Keys** — scoped, bcrypt-hashed, never stored in plaintext

**Identity federation**
- AuthGlow can also act as an **OIDC Relying Party**, delegating login to an external provider — any OIDC-compliant IdP works with just a config entry, no code
- Pre-built support for **CIE and SPID** (Italian digital identity), plus Google, Microsoft/Entra ID, Apple, Keycloak, Auth0, Okta, GitHub, and Facebook
- Auto-create/auto-link accounts by email or external ID, per-provider claims mapping, federated logout

**Authorization & admin**
- **RBAC** — roles, permissions, per-route enforcement
- **OAuth2 client management** — per-client branding, scopes, grant types, secret rotation
- **Consent screen** — configurable, with custom CSS branding per client
- **Admin dashboard** — users, OAuth2 clients, sessions, consents, API keys, roles, JWK keys, audit log
- **OAuth Playground** — built into the dashboard, exercises every flow (Authorization Code, PKCE, Client Credentials, Device Code, Introspection, Revocation) against your own running instance

**Security & operations**
- **Self-rotating JWT signing keys** — RSA keypairs encrypted at rest, auto-rotated on a schedule, safe to share across multiple instances
- Rate limiting, CSRF protection, configurable CORS, OWASP security headers, HTTPS enforcement
- Structured audit log for every auth event and admin action
- **White-labeling** — logo, colors, company name, and legal links via environment variables, applied uniformly across login, dashboard, admin, and consent pages, with light/dark mode

**Infrastructure**
- **No database** — file-based storage by default, swaps to S3, GCS, or Azure Blob with one `STORAGE_BACKEND` value
- Single `Dockerfile`, single volume for persistence
- Zero message queue, zero cache cluster — just files

> Full catalog with every endpoint: [FEATURES.md](FEATURES.md)

---

## 🖥️ Screenshots

<p align="center">
  <img src="images/homepage.png" alt="AuthGlow sign-in screen with passkey support" width="48%">
  <img src="images/profile.png" alt="AuthGlow admin dashboard and user profile" width="48%">
</p>

---

## 🚀 Quick Start

The full experience — login screen, MFA, passkeys, admin dashboard, OAuth Playground — needs **both** the backend (API) and the frontend (UI) running. It's two terminals and about three minutes.

**Prerequisites:** Python 3.11+, Node.js 20.19+ (or 22.12+), Git.

### Terminal 1 — Backend

```bash
git clone https://github.com/davideconsonni/authglow.git
cd authglow/backend

python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -r requirements.txt   # pulls in S3/GCS/Azure SDKs too, even for local-only use — normal, give it a minute
cp .env.example .env
# open .env and set a real SECRET_KEY (32+ random characters)

python main.py
```

The API is now live at **http://localhost:8000** (Swagger UI at `/docs`). Look for a line containing `setup_token_generated` in the console output and copy the `token` value — you'll need it in a second.

### Terminal 2 — Frontend

```bash
cd authglow/frontend
cp .env.example .env
# the shipped default points at :8001 — change it to:
# VITE_API_URL=http://localhost:8000

npm install
npm run dev
```

Open **http://localhost:5173/setup**, paste the setup token from Terminal 1, and create your admin account. From there, sign in normally — passkeys, MFA, and the rest of the dashboard are all there.

> No client to configure first: a default OAuth2 client ships via `OAUTH2_CLIENT_ID` / `OAUTH2_CLIENT_SECRET` in `.env.example`, so the OAuth Playground works immediately.

<details>
<summary><strong>Just want the API, no UI? (Docker)</strong></summary>

The Dockerfile packages the **backend only** — a pure REST API plus Swagger docs. Useful if you already have a frontend, or you're wiring AuthGlow in as the identity provider for an existing app.

```bash
cd authglow/backend
cp .env.example .env          # set SECRET_KEY at minimum

docker build -t authglow .
docker run -p 8000:8000 -e PORT=8000 \
  --env-file .env -v ./data:/app/data \
  authglow
```

`PORT=8000` keeps the container aligned with the `BASE_URL` / `ISSUER` / `PASSKEY_ORIGIN` defaults already in `.env.example` — without it, the container listens on `8080` (the Cloud Run convention baked into the image) while your config still advertises `8000`, which breaks OIDC discovery.

</details>

---

## ⚙️ Configuration

Minimum viable `.env` to get the backend running:

```bash
SECRET_KEY=your-strong-secret-key-at-least-32-chars
BASE_URL=http://localhost:8000
STORAGE_BACKEND=file
STORAGE_PATH=./data/users
CORS_ALLOWED_ORIGINS=http://localhost:5173
```

Everything else (password policy, passkey RP settings, token lifetimes, white-labeling) has sane defaults in `backend/.env.example` — copy it and adjust as needed.

**Email providers:** `console` and `file_storage` are useful for local development. Real delivery is supported through `smtp`, `sendgrid`, `mailgun`, and `resend`. Select one with `EMAIL_BACKEND`; provider-specific examples and credentials are documented in `backend/.env.example`.

For production email, set `EMAIL_FROM_ADDRESS` to a verified sender. SMTP uses STARTTLS when `SMTP_USE_TLS=true`; SendGrid uses its v3 Mail Send API; Mailgun uses its Messages API; Resend uses its `/emails` API. Set `MAILGUN_BASE_URL=https://api.eu.mailgun.net` for Mailgun EU domains.

---

## 🏗️ Architecture

```
authglow/
├── backend/
│   ├── authglow/
│   │   ├── api/            18 FastAPI routers — the HTTP surface
│   │   ├── core/           config, crypto, rate limiting, concurrency
│   │   ├── middleware/     security headers, HTTPS enforcement, body-size limits
│   │   ├── models/         Pydantic schemas
│   │   ├── repositories/   storage layer — one fsspec-backed implementation per entity
│   │   ├── services/       business logic: JWT, OAuth2, MFA, passkeys, RBAC, email
│   │   └── templates/      Jinja2 email templates
│   ├── tests/              1,200+ unit & integration tests (pytest)
│   └── main.py             entry point
│
└── frontend/
    ├── src/
    │   ├── components/     React components (ui, layout, oauth, playground)
    │   ├── pages/          route pages (auth, admin, dashboard, setup)
    │   ├── stores/         Zustand state
    │   └── hooks/          custom hooks
    └── e2e/                Playwright end-to-end tests
```

**Stack:** Python 3.11+ / FastAPI / Pydantic v2 (backend) · TypeScript / React 19 / Vite / Tailwind / Zustand / TanStack Query (frontend).

**Persistence:** files on disk or cloud object storage via fsspec. No database, no migrations, no ORM.

---

## ☁️ Deployment

### Required Environment Variables

These have **no default value** — the app refuses to start if they're missing:

| Variable | Purpose | Min Length |
|---|---|---|
| `SECRET_KEY` | Encrypts sessions, signed cookies, and the JWT keyring at rest | 32 chars |

Generate a production-safe secret:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set it as an environment variable on your platform (Docker `--env-file`, Render dashboard, Cloud Run secrets, etc.).

### Recommended for Production

These have defaults that work locally but **must be changed** before going live:

| Variable | Default | Production Value |
|---|---|---|
| `APP_ENV` | `development` | `production` |
| `BASE_URL` | `http://localhost:8000` | Your public URL (e.g. `https://auth.example.com`) |
| `ISSUER` | `http://localhost:8000` | Same as `BASE_URL` |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000,...` | Your frontend URL(s) |
| `OAUTH2_CLIENT_ID` | `change-me-in-production` | A unique identifier |
| `OAUTH2_CLIENT_SECRET` | `change-me-in-production` | At least 32 random chars |
| `PASSKEY_RP_ID` | `localhost` | Your domain (e.g. `example.com`) |
| `PASSKEY_ORIGIN` | `http://localhost:8000` | Your public URL |

Copy `backend/.env.example` as a starting point, then override every value above.

### Platforms

| Platform | Notes |
|---|---|
| **Docker** | Backend only — see *Quick Start* above. Runs on any container host. |
| **GCP Cloud Run** | Container deploy, `STORAGE_BACKEND=gcs` |
| **AWS Lambda** | FastAPI via Mangum, `STORAGE_BACKEND=s3` |
| **Azure Functions** | Container deploy, `STORAGE_BACKEND=abfs` |
| **VPS / bare metal** | systemd service, `STORAGE_PATH=/data/authglow` |

Switch storage backend at any time — your data moves with it, just change `STORAGE_BACKEND`.

### Multiple instances? Mind the keyring

The JWT signing keyring lives at `KEYS_DIR` (default `data/keys/`) and rides on the **same fsspec layer** as users, sessions, and tokens — it honors `STORAGE_BACKEND` like everything else, and is encrypted at rest.

| Scenario | Backend | Notes |
|---|---|---|
| Single instance, local disk | `file` (default) | `KEYS_DIR` on the same volume as `STORAGE_PATH` |
| Multiple instances, shared filesystem (NFS, SAN, cluster FS) | `file` | Mount the shared FS at both `STORAGE_PATH` and `KEYS_DIR` |
| Multiple instances, each with its own disk | `s3`, `gcs`, `abfs`, … | Pick a backend every instance can read and write |
| Multiple instances, each with `STORAGE_BACKEND=file` on its own disk | ❌ broken | Every instance generates its own keyring; tokens won't verify across instances |

---

## 🧪 Testing

```bash
cd backend
pytest -q --tb=line -n auto       # ~1,250 tests, parallelized
ruff check authglow/ && mypy authglow/
```

```bash
cd frontend
npm test           # Vitest unit tests
npm run test:e2e   # Playwright end-to-end
```

---

## 📖 Documentation

- [FEATURES.md](FEATURES.md) — complete feature catalog, endpoint by endpoint
- [ARCHITECTURE.md](ARCHITECTURE.md) — directory map, request lifecycle, where to add what
- [DESIGN.md](DESIGN.md) — design system and visual language
- [AGENTS.md](AGENTS.md) — developer guide for AI coding agents
- [docs/QUICK_SETUP.md](docs/QUICK_SETUP.md) — zero-to-signed-in setup guide (local + deployed)
- [docs/CIE.md](docs/CIE.md) — Italian Electronic Identity Card (CIE) integration guide
- [docs/GOOGLE.md](docs/GOOGLE.md) — Google OIDC integration guide
- [SECURITY.md](SECURITY.md) — vulnerability reporting and scope
- [API Docs](http://localhost:8000/docs) — auto-generated OpenAPI (Swagger UI at `/docs`)

---

## 🤖 Built with AI

**100% AI-generated.** Every line of backend and frontend code, every template, every piece of documentation here was written by open-source and open-weight AI models — GLM, DeepSeek, MiniMax — under human direction. No manual coding.

I decided what to build and how. The AI wrote the code.

---

## 🐛 Help Me Break It

I'm posting this publicly because I genuinely want to see how far this thing can go — and where it fails.

Found a security issue? Please follow [SECURITY.md](SECURITY.md). Found a bug, a missing edge case, or a creative way to break a flow? Open an issue or a PR. Every bug found is a bug fixed. Criticizing is caring.

---

## 🗺️ Status

This is `main`, moving fast — no tagged releases yet. Pin a commit if you need stability.

SMTP / SendGrid / Mailgun email delivery is implemented behind the common `EmailProvider` interface. Everything else in [FEATURES.md](FEATURES.md) reflects working code.

---

## ⚠️ Disclaimer

This software is provided **as-is**, without warranty of any kind. The author assumes no responsibility for any damages, losses, or consequences arising from its use. Use at your own risk.

---

## 📄 License

MIT — see [LICENSE](LICENSE).
