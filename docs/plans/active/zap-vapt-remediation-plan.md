---
type: plan
status: active
ids: ZAP-NNN
---

# ZAP VAPT Remediation Plan — Local Dev Scan (2026-09-11)

> **Status**: active. Findings from the OWASP ZAP scans of the local dev stack.
> **Source**: ZAP 2.17.0 (`zaproxy/zap-stable` Docker image), 3 runs (baseline / full / authenticated).
> **Reports**: [`docs/vapt/`](../vapt/README.md) — `20260911-001810-baseline`, `20260911-001909-full`, `20260911-004542-auth`.
> **Runner**: `security/zap/run-zap.ps1` (+ `zap-*.yaml`). See `security/zap/README.md`.
> **Targets**: SPA `http://localhost:5173` (Vite dev server), API `http://localhost:8001` (FastAPI).

## How to use this file

Each item has a stable ID `ZAP-NNN`. Items are grouped into **workstreams sized
for one session each**. Work top-down; tick `[ ]` → `[x]` and append a short note
(commit SHA / "risk-accepted — rationale") when an item closes.

Severity here is **remediation impact** (not the raw ZAP label): `HIGH = real
bug/finding`, `MEDIUM = defense-in-depth`, `LOW = hardening`, `INFO = hygiene`.
ZAP often over-rates dev-server artefacts: every item below states a **verdict**
so you don't re-triage from scratch.

> The dev stack is **not** the production artefact. Vite (`:5173`) emits no
> security headers and serves unbundled modules; the built SPA is served by the
> backend (which does set the headers). Findings on `:5173` are dev-only unless
> the item says otherwise.

## Severity summary

| Severity               | Count | Done | Remaining |
|------------------------|-------|------|-----------|
| HIGH                   | 2     | 2    | 0         |
| MEDIUM                 | 3     | 2    | 1         |
| LOW                    | 1     | 1    | 0         |
| INFO                   | 1     | 0    | 1         |
| Closed (FP / dev-only) | 6     | 6    | 0         |

## Triage overview

| ID      | Finding                                                     | ZAP            | Verdict                   | Action                                                     |
|---------|-------------------------------------------------------------|----------------|---------------------------|------------------------------------------------------------|
| ZAP-001 | 500 on `/api/federation/login/{provider_id}` (malformed id) | High / SQLi    | **Real bug** (not SQLi)   | Fixed in tree — commit + harden base                       |
| ZAP-002 | 500 on `/api/passkey/auth/complete` (malformed body)        | High-Ind / Low | **Real bug**              | ✅ Fixed — failure event + non-raising `validate_metadata` |
| ZAP-003 | Generic 500 body leaks "Internal server error"              | Low            | **Real (minor)**          | Stable error envelope + correlation id                     |
| ZAP-004 | CSP / X-Frame-Options / XCTO / SRI missing                  | Medium         | Dev-only, but verify prod | Integration test on built SPA + docs                       |
| ZAP-005 | `WWW-Authenticate: Basic` on `/oauth2/register/*`           | Medium         | Likely risk-accept        | Confirm TLS/HSTS, document                                 |
| ZAP-006 | Sensitive data in URL (`session_token`, `token`)            | Info-Med       | Review                    | Move consent check off query if feasible                   |
| ZAP-900 | Path Traversal / SQLi / Format String on Vite/federation    | High           | **False positive**        | Closed                                                     |
| ZAP-901 | Timestamp / Suspicious Comments / Modern Web App            | Info           | **Dev-only / info**       | Closed                                                     |

---

## Workstream 1 — Unhandled 500s & error disclosure

*Session-sized. Highest value: real robustness bugs + error disclosure.*

- [x] **ZAP-001** — 500 on `GET /api/federation/login/{provider_id}` with a malformed id
  - **Verdict**: real bug; **not** SQL Injection (AuthGlow has no database). The
    `"` payload built the path `.../federation/".json` and `fsspec`/`os.open`
    raised `OSError: [Errno 22] Invalid argument` → 500.
    - **Evidence**: `full.md` → SQL Injection (High/Low), attack `"`, `HTTP/1.1 500`.
  - **Location**: `backend/authglow/repositories/file/federation.py`
    (`_provider_path`, `get_by_id`, `delete`).
  - **Fix (committed — bundled into `f67f3d7`)**: provider ids are validated
    against `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and `..` is rejected. Reads →
    `None` (→ route 404), `delete` → no-op, `create` → `ValueError` (fail closed).
    This also closes a latent path-traversal via `provider_id`.
  - **Tests**: `backend/tests/unit/repositories/file/test_federation.py`
    (`test_unsafe_provider_id_is_treated_as_missing`, `test_create_rejects_unsafe_id`).
  - **Verification**: temporary backend on `:8002` → `/api/federation/login/%22` = **404** (was 500).
  - **Remaining**:
    - [x] Commit the change — landed in `f67f3d7` (bundled with the ZAP-002 commit).
    - [ ] Restart the running `:8001` backend so the fix is live.
    - [x] Defense-in-depth — implemented:
      - shared `repositories/file/_ids.py` (`is_safe_entity_id` +
        `is_safe_base64url_id`); `federation.py` refactored to use it;
      - `BaseFileRepository._read_json` / `_read_json_versioned` / `_delete`
        treat a *path-shape* `OSError` (`EINVAL` / `ENAMETOOLONG` / `ENOTDIR` /
        `ENOENT`) as "not found" (never 500); `PermissionError` and other
        operational `OSError` still propagate;
      - passkey `credential_id` / `challenge` (base64url) and `user_id` validated
        at the repo boundary: reads → "not found", writes → `ValueError` (fail
        closed).
      - **Tests**: `tests/unit/repositories/file/test_base.py`,
        `tests/unit/repositories/file/test_passkey.py` (+ federation regression).
        Full suite **2775 passed**; `mypy` / `ruff` clean on changed files.

- [x] **ZAP-002** — 500 on `POST /api/passkey/auth/complete` with a fuzzed body
  - **Verdict**: real bug. **Root cause** (confirmed in `backend.out.log`): the
    `except` handler logged an audit event with `event_type=PASSKEY_AUTHENTICATED`
    but failure-shaped metadata. The audit layer validates metadata against
    `PasskeyAuthenticatedMetadata`, which requires `sign_count` → Pydantic
    `ValidationError` was raised *inside the `except`*, before the intended
    `HTTPException(400)`, and reached the catch-all → 500.
    - **Evidence**: `full.md` → Application Error Disclosure / Debug Error Messages,
      URL `/api/passkey/auth/complete`, `HTTP/1.1 500 Internal Server Error`,
      body evidence `Internal server error`.
  - **Location**: `backend/authglow/api/passkey.py:406-417`.
  - **Fix (A — call site)**: added `PASSKEY_AUTHENTICATION_FAILED`
    (`passkey_authentication_failed`, category `mfa`, default severity `warning`,
    `default_severity` list) in `models/audit_events.py`; added
    `PasskeyAuthenticationFailedMetadata` + registry entry in
    `models/audit_metadata.py`; the `except` now logs the failure event.
  - **Fix (B — systemic)**: `validate_metadata` is now best-effort — on a schema
    mismatch it logs `audit_metadata_validation_failed` and returns the raw
    metadata instead of raising, so the audit layer can never turn a handled
    4xx into a 500.
  - **Tests**: `tests/unit/test_audit.py`
    (`TestPasskeyAuthenticationFailedEvent`) and `tests/unit/test_passkey.py`
    (`TestCompleteAuthenticationErrorHandling::test_malformed_body_returns_400_not_500`).
  - **Verification**: 63 passed; `mypy` clean. Pre-existing `I001`/`F401` in
    `test_audit.py` are untouched (present at HEAD).

- [x] **ZAP-003** — Generic 500 envelope leaks debug text
  - **Verdict**: real, minor. Same root as ZAP-002; also a systemic guarantee.
  - **Task**: verify `register_global_error_handler` (and
    `register_oauth2_error_handler`) return a stable JSON error with a
    correlation id, and that `APP_ENV=production` never includes debug detail.
  - **Location**: `backend/authglow/api/error_handlers.py`
    (`register_global_error_handler`), `backend/authglow/middleware/request_id.py`
    (`REQUEST_ID_SCOPE_KEY`), `backend/main.py` (registration). Note: the plan's
    old pointer to `oauth_errors.py:90` covers only the OAuth2 protocol envelope
    (already RFC 6749-shaped, untouched) — the generic 500 lives in
    `error_handlers.py`.
  - **Acceptance**: an unexpected exception produces a generic body with a
    request id; the real cause is only in the server log/audit.
  - **Done (uncommitted working tree)**: `unhandled_exception_handler` echoes
    `request_id` in body + `X-Request-ID` header and passes it explicitly to the
    audit event; `RequestIDMiddleware` stashes the id on the ASGI scope.
    Key discovery: Starlette installs an `Exception` handler on the outermost
    `ServerErrorMiddleware`, so by handler time the contextvar is unbound and
    only the scope survives — without the stash, prod 500s had no header and
    `request_id: null` in audit. Tests: `test_global_error_handler.py` (4 passed:
    body↔header↔audit correlation, inbound echo, no-leak); `test_vapt042` +
    `test_audit` green (87 total); `ruff`/`mypy` clean.

---

## Workstream 2 — Security headers on the production SPA (ZAP-004)

- [x] **ZAP-004** — CSP / X-Frame-Options / X-Content-Type-Options / SRI
  - **Verdict**: dev-only for `:5173`; **must be verified** for the built SPA.
    `SecurityHeadersMiddleware` already sets CSP, X-Frame-Options,
    X-Content-Type-Options, Referrer-Policy, Permissions-Policy and (prod) HSTS on
    every non-docs path (`backend/authglow/middleware/security_headers.py:39-68`).
  - **Evidence**: `full.md` / `auth.md` — all header alerts are on `:5173` only.
  - **Tasks**:
    - [x] Add an integration test: with `FRONTEND_DIST_DIR` set, `GET /` returns
      `Content-Security-Policy`, `X-Frame-Options` and `X-Content-Type-Options`.
    - [x] Confirm `settings.csp_header` is non-empty for production and that dev
      (`:5173`) bypassing the backend is documented as expected.
    - [x] SRI (`Sub Resource Integrity`): the only instance is the Google Fonts
      `<link>` (dynamic CSS → SRI impractical). Either self-host the fonts or
      record a documented risk-acceptance.
  - **Acceptance**: test green; a one-line note in the VAPT README / plan records
    the dev-only rationale for `:5173`.
  - **Done (uncommitted working tree)**: `TestBuiltSpaHeaders` in
    `tests/integration/test_security_headers.py` (3 tests: `GET /` + `/dashboard`
    via real `FileResponse` behind the middleware with dynamic CSP assert +
    spot-check, default `csp_header` non-empty via `test_settings`) — 20/20 green
    in file; zero new ruff violations (7 pre-existing at HEAD unchanged);
    dev-only + SRI risk-accept note in `docs/vapt/README.md`. No production code
    touched. Residuals declared: the test replicates `main.py` wiring instead of
    importing it (import side effects on the settings singleton) — true wiring
    coverage is the ZAP re-scan; follow-up (separate item): fail-closed guard if
    `csp_header` is ever blanked via admin runtime override (`_add_header`
    silently skips empty values).

---

## Workstream 3 — OAuth2 DCR auth method (ZAP-005)

- [x] **ZAP-005** — `WWW-Authenticate: Basic realm="OAuth2"` on `/oauth2/register/{client_id}`
  - **Verdict**: likely risk-accept. `client_secret_basic` is a valid DCR client
    authentication method (RFC 7591/7592); the alert is about Basic over **cleartext HTTP**.
  - **Evidence**: `full.md` / `auth.md` — DELETE + GET `/oauth2/register/client_id`,
    header `Basic realm="OAuth2", Bearer realm="OAuth2"`.
  - **Location**: `backend/authglow/api/oidc.py:873-925`, `:962`.
  - **Tasks**:
    - [x] Confirm production runs behind TLS with HSTS (`enforce_hsts` /
      `APP_ENV=production`), so Basic is never sent in cleartext.
    - [x] Decide: accept (documented) or drop the Basic challenge for DCR in
      favour of `private_key_jwt`.
  - **Acceptance**: decision recorded with rationale.
  - **Decision (uncommitted working tree): RISK-ACCEPT, no code change.**
    Production 301-redirects HTTP→HTTPS before routing (`HttpsEnforcementMiddleware`,
    `enforce_https` default true) so credentials are never processed in cleartext,
    and emits HSTS (`enforce_hsts` default true) — both defaults pinned by the new
    `TestTlsDefaultsForBasicAuth` in `tests/integration/test_security_headers.py`
    (22 passed). Dropping Basic on DCR alone was rejected:
    incoherent (token endpoint + client defaults stay Basic-first) and breaking
    (forces asymmetric crypto on every DCR client) with no real-vector gain on TLS;
    the 401 already advertises Bearer-JWT alongside Basic for capable clients.
    Note in `docs/vapt/README.md`. Follow-up (separate ops item): HSTS `preload`
    directive + preload-list submission for the first-visit downgrade gap.

---

## Workstream 4 — Sensitive data in URLs (ZAP-006)

- [ ] **ZAP-006** — review Information Disclosure — Sensitive Information in URL
  - **Verdict**: review. Some are OAuth-standard, some are fixable.
  - **Evidence**: `auth.md` — `/api/oauth2/consent/check?session_token=...`,
    `/?token=...`, `/oauth2/logout?id_token_hint=...`, admin list filters `?email=...`.
  - **Tasks**:
    - [ ] `/api/oauth2/consent/check` carries `session_token` in the query —
      evaluate moving to `POST` body (avoid Referer/log leakage). Check the SPA caller.
    - [ ] `/oauth2/logout?id_token_hint=` / `state` are OIDC RP-Initiated Logout
      parameters — keep; document as accepted.
    - [ ] Admin list `?email=` filters are server-to-server with the email only in
      access logs — accept; confirm PII logging policy applies.
  - **Acceptance**: decision + code change for `consent/check` if feasible.

---

## Closed — false positives / dev-only (no action)

- [x] **ZAP-900** — Path Traversal on `/node_modules/.vite/deps/*?v=` → **FP** of the Vite dev server.
- [x] **ZAP-900** — SQL Injection / Format String on `/api/federation/*` → **FP**; the underlying cause is ZAP-001.
- [x] **ZAP-901** — Timestamp Disclosure (`react-dom_client.js`), Suspicious Comments (`node_modules`, Vite client), Modern Web Application, Authentication Request Identified, Session Management Response Identified, User Agent Fuzzer → info / dev-only.

---

## Environment / continuation notes

Read this before starting a session — it saves re-discovering the setup.

- **ZAP runs in Docker**: `zaproxy/zap-stable:2.17.0` (already pulled); Docker
  Desktop must be running. The Windows `.exe` installer is blocked by antivirus
  (false positive) — do **not** try `winget`/portable.
- **Targets must be up**: backend on `:8001` and a `0.0.0.0`-bound Vite on
  `:5173` with `VITE_API_URL=http://host.docker.internal:5173` (same-origin via
  the dev proxy added to `frontend/vite.config.ts`). See `security/zap/README.md`.
- **Demo credentials**: never hardcode them; `run-zap.ps1` reads the password from
  `GET /api/meta` and it **rotates on every backend restart**.
- **ZAP-001 is fixed in the working tree but uncommitted**, and the backend
  currently listening on `:8001` still serves the old code — restart it.
- Leftover backend processes on `:8001` may not be killable from an agent shell
  (elevated / other session); prefer restarting over killing.
- `frontend/vite.config.ts` intentionally carries the dev proxy + `allowedHosts`.

## Suggested session order

| Session    | Scope                    | Outcome                                                                              |
|------------|--------------------------|--------------------------------------------------------------------------------------|
| A          | ~~ZAP-002~~ ✅ + ZAP-003 | Failed passkey auth fixed (400, not 500); verify unexpected-error envelope (ZAP-003) |
| A (finish) | ZAP-001 remaining        | Commit + restart backend; base-repo OSError hardening decision                       |
| B          | ZAP-004                  | Header integration test on built SPA + SRI decision                                  |
| C          | ZAP-005                  | DCR auth-method decision recorded                                                    |
| D          | ZAP-006                  | `consent/check` off the query string + decisions                                     |

## Re-scan (definition of done)

After each workstream, re-run the relevant ZAP mode and diff the alert set:

```powershell
pwsh -File security/zap/run-zap.ps1 -Mode auth -Docker -Yes
```

A finding is closed when the alert no longer appears in a fresh authenticated run,
or when its risk is explicitly accepted here with a rationale.

## Suggested skills for the next session

- `diagnosing-bugs` — for ZAP-003 (unexpected-error path / error envelope) if needed.
- `tdd` — add the regression tests for ZAP-003/ZAP-004 (ZAP-002 done).
- `code-review` — after the change set, review against this plan + repo standards.
