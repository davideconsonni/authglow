<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="backend/authglow/static/images/authglow_full_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="backend/authglow/static/images/authglow_full_light.png">
    <img alt="AuthGlow Logo" src="backend/authglow/static/images/authglow_full_light.png" width="400">
  </picture>
</p>

<h1 align="center">AuthGlow</h1>

<p align="center">
  <strong>The serverless identity provider I always wanted but couldn't find — so I built it and open-sourced it.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/AI%20Generated-100%25-blueviolet.svg" alt="AI Generated">
</p>

---

## What is AuthGlow?

AuthGlow is a **self-contained, serverless-ready identity provider** — OAuth 2.0 / OpenID Connect authorization server, user management, MFA, Passkeys, RBAC, and more. No database required.

It stores everything as files (JSON by default), runs anywhere with zero external dependencies, and scales to cloud storage (S3, GCS, Azure Blob) by changing one environment variable — no code changes needed.

**Simple to set up. Easy to customize. Built to be extended.**

---

## Why I Built This

I spent way too long looking for an identity provider that was **truly serverless**, easy to plug into any stack, didn't force me into a specific database, and let me tweak every little thing without fighting some enterprise licensing model.

I never found one.

So I sat down, described exactly what I wanted to a handful of AI models, and after many iterations AuthGlow was born. I use it for my own projects. Now you can too. It's free, MIT-licensed, and I'll keep improving it.

---

## Features

- **OAuth 2.0 & OIDC** — Full authorization server: Authorization Code + PKCE, Client Credentials, Refresh Token rotation with theft detection, Token Introspection (RFC 7662), Revocation (RFC 7009), RP-Initiated Logout
- **Passkeys (WebAuthn)** — Passwordless authentication with FIDO2. Works with Touch ID, Windows Hello, YubiKey
- **Multi-Factor Authentication** — TOTP (Google Authenticator) + backup codes + trusted device remember
- **RBAC** — Roles, permissions, and user-role assignments. Protect your API routes with granular access control
- **API Keys** — Scoped keys for programmatic access. Bcrypt-hashed, never stored in plaintext
- **Admin Dashboard** — Manage users, OAuth2 clients, sessions, consents, API keys, and view audit logs
- **Audit Logging** — Every auth event, admin action, and security event is tracked
- **Serverless Storage** — Data lives on the filesystem (JSON) by default. Swap to S3, GCS, or Azure Blob by changing `STORAGE_BACKEND`
- **Customizable UI** — Light/dark mode, company branding, colors — everything set via environment variables
- **Docker-Ready** — Single Dockerfile, single volume for persistence, one command to run

> Full feature catalog: [FEATURES.md](FEATURES.md)

---

## Quick Start

### Prerequisites

- **Python** 3.10 or newer
- **Node.js** 18 or newer (for the frontend)
- **Git**

### 1. Backend (FastAPI)

```bash
git clone https://github.com/davideconsonni/authglow.git
cd authglow/backend

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
.venv\Scripts\activate             # Windows

# Install dependencies
pip install -r requirements.txt

# Configure your environment
cp .env.example .env
# IMPORTANT: Edit .env and set a strong SECRET_KEY (at least 32 characters)

# Run
python main.py
```

The backend starts at **http://localhost:8000**.  
On first run, visit `/setup` to create your admin account.

### Minimum `.env` configuration

At the very least, make sure these are set in your `backend/.env`:

```bash
SECRET_KEY=your-strong-secret-key-at-least-32-chars
BASE_URL=http://localhost:8000
STORAGE_BACKEND=file            # or s3 / gcs / abfs
STORAGE_PATH=./data/users
CORS_ALLOWED_ORIGINS=http://localhost:5173
```

### 2. Frontend (React + Vite) — optional

AuthGlow works perfectly with its built-in Jinja2 templates. If you prefer the React SPA:

```bash
cd authglow/frontend

cp .env.example .env            # sets VITE_API_URL=http://localhost:8000

npm install
npm run dev
```

The frontend starts at **http://localhost:5173** and connects to the backend automatically.

### 3. Docker (alternative)

```bash
docker build -t authglow .
docker run -p 8000:8000 -v ./data:/app/data --env-file .env authglow
```

---

## Built with AI

**100% AI-generated.** Every line of code, every template, every piece of documentation was written by AI models — Claude, Gemini, MiniMax, GLM, Deepseek — under human direction. No manual coding. It's a glimpse of what human-AI collaboration looks like in 2026.

I decided what to build and how. The AI wrote the code.

---

## Help Me Break It

I'm posting this publicly because I genuinely want to see how far this thing can go — and where it fails.

**If you find a security bug, an edge case, or a creative way to exploit something, open an issue or a PR.** I'm not afraid of bad news. Every bug found is a bug fixed. Criticizing is caring.

---

## Disclaimer

This software is provided **as-is**, without warranty of any kind, express or implied. The author assumes no responsibility or liability for any damages, losses, or consequences arising from its use, misuse, or deployment. Use at your own risk.

---

## License

MIT — see [LICENSE](LICENSE).
