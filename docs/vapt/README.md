# VAPT reports

Results of the local ZAP scans (OWASP ZAP 2.17.0 in Docker, official
`zaproxy/zap-stable` image). Scanned 2026-09-11 against the local dev stack:

| Target                | URL                     |
|-----------------------|-------------------------|
| SPA (Vite dev server) | `http://localhost:5173` |
| API (FastAPI)         | `http://localhost:8001` |

> These scans assess the **development setup**, not the production artifact.
> The Vite dev server is not the built SPA (the single-container image serves the
> pre-built SPA from the backend). Findings located on `:5173` are dev-only unless
> stated otherwise.
>
> **ZAP-004 note**: header findings (CSP, X-Frame-Options, …) on `:5173` are
> dev-server artefacts — Vite emits no security headers by design. The production
> SPA is served by the backend with the full header set (covered by
> `TestBuiltSpaHeaders` in `backend/tests/integration/test_security_headers.py`).
> SRI is a documented risk-accept for the Google Fonts stylesheet link
> (`frontend/index.html`): vendor CSS is generated per request, so hash-based
> integrity is inapplicable; `style-src` / `font-src` stay allow-listed to
> `fonts.googleapis.com` / `fonts.gstatic.com`.
>
> **ZAP-005 note**: the `WWW-Authenticate: Basic` challenge on the DCR
> management endpoints is a legitimate RFC 7591/7592 method, exploitable only
> over cleartext HTTP. In production HTTP never reaches the handler (301 to
> HTTPS before routing, `enforce_https`) and HSTS is emitted (`enforce_hsts`);
> both defaults are pinned by `TestTlsDefaultsForBasicAuth`. Correct TLS
> termination at the deploy edge is a prerequisite.
>
> **ZAP-006 note**: bearer tokens no longer travel in URLs on the consent
> path — `POST /api/oauth2/consent/check` takes `session_token` in the
> Form body (the legacy GET query transport returns 405). Kept as-is by
> design: email magic-link `?token=` (must be a GET link), OIDC
> `id_token_hint` on logout (standard params, POST alternative exists),
> admin `?email=` filters (RBAC-gated server-to-server, PII hashed in
> audit). Page-navigation tokens (`mfa_session_token`, MFA `session_token`)
> stay in URLs for now — the structural fix is cookie transport on the
> federated-flow model, tracked as follow-up.

## Runs

| Directory                                             | Mode             | Auth                       | Summary                         |
|-------------------------------------------------------|------------------|----------------------------|---------------------------------|
| [20260911-001810-baseline](20260911-001810-baseline/) | passive baseline | no                         | 3 Medium, 1 Low, 2 Info         |
| [20260911-001909-full](20260911-001909-full/)         | active full      | no                         | 2 High, 5 Medium, 4 Low, 6 Info |
| [20260911-004542-auth](20260911-004542-auth/)         | active full      | browser login (demo admin) | 4 Medium, 3 Low, 4 Info         |

Each directory contains `*.html` (readable), `*.json` (machine-readable) and
`*.md` (Markdown summary).

## Reproduce

```powershell
pwsh -File security/zap/run-zap.ps1 -Mode baseline -Docker
pwsh -File security/zap/run-zap.ps1 -Mode full -Docker
pwsh -File security/zap/run-zap.ps1 -Mode auth -Docker
```

See `security/zap/README.md` for prerequisites and configuration.

## Remediation

Tracked in [`../plans/active/zap-vapt-remediation-plan.md`](../plans/active/zap-vapt-remediation-plan.md).
