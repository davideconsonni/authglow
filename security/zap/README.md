# AuthGlow — local VAPT with OWASP ZAP

Automated security scans of the **local dev stack**:

| Target | URL | Notes |
|---|---|---|
| SPA (Vite dev server) | `http://localhost:5173` | client-side routed (React) |
| API (FastAPI) | `http://localhost:8001` | OpenAPI at `/openapi.json` |

> These scans assess the **development setup**. The Vite dev server is not the
> production artifact (the single-container image serves the pre-built SPA from
> the backend). Treat results on `:5173` as indicative, not final.

## Prerequisites

1. Backend running on `:8001` with `DEMO_MODE=true` (`GET /api/meta` exposes the
   live demo credentials) and a working `/openapi.json`.
2. Frontend running on `:5173`.
3. OWASP ZAP installed (see below).

### Install ZAP

The Windows installer needs admin elevation (it prompts UAC):

```powershell
winget install --id ZAP.ZAP --source winget   # installs bundled Temurin JRE 17
```

If you cannot elevate, use the **portable** build with an existing JRE:

```powershell
# a JRE is already present at C:\Program Files\Eclipse Adoptium (installed by winget)
$dst = "$PSScriptRoot\zap"
Invoke-WebRequest `
  -Uri "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Crossplatform.zip" `
  -OutFile "$env:TEMP\ZAP_2.17.0_Crossplatform.zip"
Expand-Archive "$env:TEMP\ZAP_2.17.0_Crossplatform.zip" -DestinationPath $dst
```

The script auto-detects `zap.bat` in the usual install paths, under
`security/zap/zap/`, or wherever `ZAP_HOME` points. Override with `-ZapPath`.

## Usage

```powershell
# Passive baseline (safe, no payloads) — SPA + API
pwsh -File security/zap/run-zap.ps1 -Mode baseline

# Unauthenticated active scan (INVASIVE) — backs up backend/data first
pwsh -File security/zap/run-zap.ps1 -Mode full

# Authenticated active scan (browser login as the demo admin, INVASIVE)
pwsh -File security/zap/run-zap.ps1 -Mode auth -Yes

# Everything, in order
pwsh -File security/zap/run-zap.ps1 -Mode all
```

`-Yes` skips the confirmation prompt for invasive modes.

## What each mode does

| Mode | Plan | Auth | Invasive |
|---|---|---|---|
| `baseline` | `zap-baseline.yaml` | no | no |
| `full` | `zap-full.yaml` | no | yes |
| `auth` | `zap-auth.yaml` | browser (demo admin) | yes |

`full` / `auth` import the OpenAPI definition (`/openapi.json`) so the API
surface is scanned endpoint by endpoint, and use the AJAX spider for the
client-side-routed SPA.

## Output

```
security/reports/<timestamp>-<mode>/
  baseline|full|auth.html    readable report (open in a browser)
  baseline|full|auth.json    machine-readable (tooling / diffing)
  baseline|full|auth.md      Markdown summary
security/backups/data-<timestamp>/   pre-scan snapshot of backend/data
```

`reports/` and `backups/` are gitignored.

## Authentication details

`auth` mode uses ZAP's **Browser-based Authentication** (Authentication Helper
add-on):

- login page `http://localhost:5173/auth/login`
- fields `input[type="email"]`, `#password`, submit `button[type="submit"]`
- headless Chrome (`browserId: chrome-headless`)
- login verified by polling `GET http://localhost:8001/api/users/me`
  (`loggedInRegex: "email"`, `loggedOutRegex: "detail"`)

The password is read at runtime from `GET /api/meta` and injected into a
temporary plan in `%TEMP%` — never written into the repository. Demo passwords
rotate on every backend restart, so always source them from `/api/meta`.

Cookies are host-scoped (not port-scoped), so one login covers both `:5173`
and `:8001`.

If browser login fails, try `browserId: firefox-headless` (Firefox may be
auto-downloaded by ZAP) or run ZAP's GUI once and enable authentication
diagnostics to inspect the recorded login.

## Triage guidance

Expected / non-issues in this setup:

- **Missing security headers on `:5173`** — the Vite dev server emits none; the
  backend sets OWASP headers. Not representative of production.
- **CSP / HSTS findings on `:8001`** — HSTS is only applied when
  `APP_ENV=production`; dev runs intentionally omit it.
- **Exposed demo credentials at `/api/meta`** — by design (`DEMO_MODE=true`).
- **Verbose errors / `/docs` open** — dev defaults (`ENABLE_DOCS=true`).

Confirmed findings should reference the source (`file:line`). Cross-check every
`High` / `Medium` before reporting.

## CI (optional)

Only `baseline` is suitable for CI: it is non-invasive and deterministic.
Do **not** run `full` / `auth` in CI against shared environments.
