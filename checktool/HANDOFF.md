# checktool — Handoff plan (remaining groups)

This document is the entry point for a fresh session that will add more check
groups to the AuthGlow console checktool. Read it top to bottom before writing
code. It contains everything you need: architecture, the group contract, the
conventions, the verification workflow, and a per-group backlog with concrete
endpoints.

The tool is **black-box**: it talks to a running AuthGlow over HTTP with
`httpx` and never imports `authglow`. Keep it that way.

---

## 1. Where everything lives

```
checktool/
├── pyproject.toml            # deps (httpx, rich, questionary, PyJWT[crypto]) + ruff/mypy/pytest config
├── requirements.txt          # pinned mirror of the deps
├── run.ps1 / run.bat / run.sh# launchers (auto-create .venv + editable install)
├── HANDOFF.md                # this file
├── checktool/                # the package
│   ├── cli.py                # argparse + orchestration; run entry point
│   ├── client.py             # ApiClient: bearer, 429 backoff, CSRF retry, OAuth2/PKCE helpers
│   ├── bootstrap.py          # instance discovery + admin credential resolution/login
│   ├── console.py            # rich UI + questionary prompts
│   ├── config.py             # CheckConfig (base_url default http://127.0.0.1:8001, run_id/namespace)
│   ├── registry.py           # Group base + GroupContext + @register_group
│   ├── results.py            # CheckResult / GroupResult / RunReport (+ Markdown)
│   ├── runner.py             # sequential group execution
│   ├── groups/               # one file per group (+ __init__.py that imports them all)
│   └── coverage/audit.py     # static frontend→backend gap report
└── tests/                    # pytest unit tests (no network)
```

Run: `python -m checktool` (from `checktool/`) or the launchers.
Lint/type/test: see §5.

## 2. The group contract

A group is one **self-consistent** unit: it creates its own fixtures
(namespaced), exercises a feature end to end, asserts results, and cleans up.
It must not depend on any state produced by another group.

Minimal group:

```python
"""Group: <what it verifies>."""

from checktool.registry import Group, GroupContext, register_group


@register_group
class ExampleGroup(Group):
    slug = "example"                       # unique; the CLI --groups key
    title = "Example"
    description = "Short, plain-language sentence shown in the UI."
    requires_admin = True                  # True => cli logs in an admin first

    def run(self, ctx: GroupContext) -> None:
        resp = ctx.request("Something happens", "POST", "/api/things", json={...})
        ctx.check("POST /api/things creates a thing", resp.status_code == 201, ctx.evidence(resp))
```

Register it by adding the module to the import list in
`checktool/groups/__init__.py` (import order = display/run order).

`GroupContext` API (see `registry.py`):

| Member | Use |
|---|---|
| `ctx.api` | the admin-authenticated `ApiClient` |
| `ctx.new_client()` | a fresh unauthenticated client (act as another user) |
| `ctx.name(suffix)` | namespaced fixture name: `ct-<runid>-<suffix>` |
| `ctx.email(label)` | namespaced email: `ct-<runid>-<label>@example.com` |
| `ctx.request(desc, method, path, **kw)` | narrate a step + do the HTTP call |
| `ctx.check(name, ok, evidence="")` | record + display one assertion |
| `ctx.warn(msg)` | non-fatal warning shown in the report |
| `ctx.skip(name, reason)` | mark a check as intentionally skipped |
| `ctx.admin_email` / `ctx.admin_password` | the logged-in admin credentials (for re-login / acting as admin) |
| `ctx.evidence(resp)` | compact `HTTP <code>: <snippet>` string |

## 3. Conventions and gotchas (read this — saves you a debug cycle)

- **Emails must use `@example.com`.** `@example.test`, `.invalid`, `.localhost`
  are rejected by `email-validator` (HTTP 422). Always use `ctx.email(...)`.
- **Bearer bypasses CSRF.** `ApiClient` sends `Authorization: Bearer <token>` on
  every call; the CSRF middleware lets credentialed requests through. For calls
  you make with an explicit header, pass `use_bearer=False` and set the header
  yourself (see how `auth.py` / `oauth2.py` groups do it).
- **One admin login per run.** `cli` logs in once; reuse `ctx.api` and (if you
  must act as the admin user) `ctx.admin_email/admin_password` + `ctx.new_client()`.
  Avoid extra `authorize`/`token` calls: `POST /api/oauth2/authorize` is 30/min,
  `/oauth2/token` 60/min, and many admin endpoints are 20–120/min.
- **The real authorize path is `/api/oauth2/authorize`** (not the
  `/oauth2/authorize` advertised in discovery). `ApiClient.authorize_code`
  already does login + consent + PKCE and returns `{code, state, iss, verifier}`.
- **Always clean up in `finally`.** Deletion failures are `ctx.warn(...)`, never
  a failed check. Set the tracked id to `None` after a successful delete so the
  `finally` block does not double-delete.
- **Safeword handshake** (OAuth client rotate-secret / rotate-jwt-key, API-key
  rotate/delete): first `POST .../challenge` → `{challenge_id, word}`, then the
  destructive call with body `{challenge_id, word}`.
- **Rate limits that will bite**: password reset request `5/hour`, email resend
  `3/hour`, phone `5/hour`, MFA verify `10/min`. Do at most one per run.
- **External dependencies must not fail the run.** If a group needs an
  authenticator, an external IdP, or a reachable webhook receiver, either test
  only the local/CRUD part or `ctx.skip(...)` with a clear reason. Never leave a
  red check for a capability the environment cannot provide.
- **Demo-only affordances**: `GET /api/demo/inbox?email=...` returns
  `{"emails": [{"body_text": ...}]}` (newest first) and is `404` outside demo
  mode. Use it to harvest email/reset codes. Guard with the mode (read
  `/api/meta`).
- **Acting as a normal user**: `ctx.new_client().admin_login(email, password)`
  (the name is historical — it is just password login). Request scope
  `"openid profile email read offline_access"` (do NOT ask `write` for a
  `read`-only user or the token exchange fails with `invalid_scope`).

### 3.1 Artifacts & curl replay

Groups can publish the secrets / ids they create so the operator can reuse
them or replay the calls by hand:

- `ctx.expose(label, value, note="", secret=True, api=None)` prints the
  value on the console and records it in the report. Pass `api=` when the
  value came from a per-user `ctx.new_client()` rather than the admin
  client (otherwise the attached curl would be the wrong request).
- `--show-curl` prints an equivalent `curl` command after **every**
  request (the live bearer token is included, hence the banner warning);
  `--curl-shell {bash,powershell}` overrides the platform default.
- `--no-secrets` masks created secrets both on the console and in the
  report.
- `--report <file>` gains an **Artifacts & replay** section listing every
  exposed value with the curl that produced it.

## 4. Definition of done (every new group)

1. `python -m checktool --base-url http://127.0.0.1:<port> --groups <slug>` is
   **all green** against a live demo instance.
2. It runs green against a fresh non-demo instance too (or the parts that
   cannot be green there are `ctx.skip`ped with a reason).
3. It cleans up: run it twice in a row; the second run must not fail with
   "already exists".
4. Unit tests added when there is non-trivial pure logic (parsers, code
   extraction, cleanup selection).
5. `ruff`, `mypy`, `pytest` clean (§5).
6. The run is idempotent and safe on a shared instance (namespaced names,
   non-destructive except its own fixtures).

## 5. Verification workflow

The tool's own `.venv` only has runtime deps. Use the backend venv (which has
dev tools) from `checktool/`:

```powershell
$py = "..\backend\.venv\Scripts\python.exe"
& $py -m ruff check .
& $py -m mypy checktool
& $py -m pytest tests -q
```

Live smoke (start a demo backend on a spare port first):

```powershell
# terminal A (from backend/): DEMO_MODE=true uvicorn main:app --port 8001
.\run.ps1 --base-url http://127.0.0.1:8001 --groups <slug>
```

Useful existing helpers to copy from: `groups/api_keys.py` (safeword handshake,
use-then-verify), `groups/oauth2.py` (DCR + PKCE + ID-token verify + cleanup),
`groups/rbac.py` (create permission/role, assign, positive + negative check,
act as a normal user).

## 6. Status

Implemented and green on a demo instance: `bootstrap`, `auth`, `oauth2`,
`api_keys`, `rbac`, `admin_users`, plus **every backlog group in §7**
(`user_profile`, `federation`, `claim_policy`, `sessions`, `admin_insights`,
`mfa`, `email_verification`, `password_reset`, `device_auth`, `par`, `consents`,
`oauth_clients`, `webhooks`, `jwk_keys`, `settings`, `phone_verification`,
`passkeys`, `demo_inbox`). `pyotp` was added to the tool deps for the `mfa`
group; local/CI code extraction lives in `checktool/helpers.py` with unit tests.

Environment-conditional checks (skipped/warned, never red) so the run stays
green against the demo instance:

- `email_verification`: the repo `.env` sets `EMAIL_BACKEND=resend` without a
  key, so `POST /api/email/resend-verification` returns 400 "Failed to send"
  while the demo inbox still captures the code → warning + accepted.
- `phone_verification`: a real SMS provider (Infobip) rejects an arbitrary
  destination → the request step is skipped; the verify step is always skipped
  (the code never leaves the server).
- `webhooks`: the signed test delivery targets an unreachable loopback receiver
  → warning on the expected failure.
- `jwk_keys`: the rotate/revoke steps only run on a local target or with
  `--yes`; the "active key cannot be revoked" check always runs.

All new groups were verified individually with
`python -m checktool --base-url <demo> --groups <slug>`;
`ruff`, `mypy` and `pytest` are clean.

## 6.1 Known backend quirks found while writing groups

- Self-service `POST /api/profile/me/change-email` updates the profile record
  but not the login index: the **old** address still authenticates (and the new
  one does not) until the index moves. `user_profile` therefore keeps its
  lifecycle assertions on a second fixture whose address never changes.
- `POST /api/admin/tokens/refresh/{id}/revoke` and `.../sessions/revoke-all`
  make a refresh attempt fail with **401 `invalid_grant`** (not 400).
- `POST /api/admin/oauth-consents/{id}/revoke` is a **soft revoke**: the record
  stays listed with `revoked: true`.
- `POST /api/phone/request` authenticates the caller; `POST
  /api/email/resend-verification` is public but, when called with a bearer,
  uses the **bearer's own email** and ignores the body — pass it
  unauthenticated to resend for an arbitrary address.
- Re-enabling global rate limits via `PUT /api/admin/rate-limits/config` after
  `--relax-rate-limits` can surface a slowapi `UnboundLocalError` (500) even
  though the setting was persisted; re-read `/status` to confirm.

---

## 7. Backlog — groups to implement

Effort: S/M/L. "external" = needs something the environment usually lacks.

### 7.1 [x] `mfa` — MFA lifecycle (M, external: needs TOTP generation)
- `requires_admin = True` (for the admin-managed reset path) — or manage a
  dedicated user; either works.
- Add dependency `pyotp` to `pyproject.toml` + `requirements.txt` (backend has
  it; the tool does not yet).
- Steps (act as a dedicated user created in-fixture):
  1. login → `POST /api/mfa/enroll` (bearer) → capture `secret`.
  2. compute TOTP with `pyotp.TOTP(secret).now()` → `POST /api/mfa/verify {"code": ...}`.
  3. `GET /api/mfa/status` → `enabled`/`verified`, `backup_codes_remaining`.
  4. fresh login as the user → `POST /api/oauth2/authorize` returns
     `{mfa_required: true, session_token}` → `POST /api/mfa/verify-login
     {"session_token", "code"}` → tokens.
  5. use a backup code from enroll to prove recovery; then
     `POST /api/mfa/regenerate-backup-codes`.
  6. `DELETE /api/mfa/disable` (with a fresh TOTP) → status disabled.
- Cleanup: delete the user via admin.
- Gotchas: MFA verify endpoints are 10/min; TOTP is time-based — call
  `pyotp.TOTP(secret).now()` immediately before each verify.

### 7.2 [x] `oauth_clients` — admin OAuth2 client CRUD (M)
- `requires_admin = True`.
- Steps:
  1. `POST /api/oauth-clients` body `OAuth2ClientCreate` (`client_name`,
     `redirect_uris`, `allowed_scopes`, `grant_types`, `token_endpoint_auth_method`)
     → 201 + `client_secret` (shown once).
  2. `GET /api/oauth-clients`, `GET /api/oauth-clients/{id}`, `PUT .../{id}`.
  3. `POST .../{id}/deactivate` → `GET` shows `is_active=false`; `POST .../{id}/activate`.
  4. rotate-secret: `POST .../{id}/rotate-secret/challenge` → `POST .../{id}/rotate-secret`
     with `{challenge_id, word}`; assert a new secret is returned.
  5. rotate-jwt-key: `POST .../{id}/rotate-jwt-key/challenge` → `POST .../{id}/rotate-jwt-key`.
  6. `DELETE /api/oauth-clients/{id}`.
- Cleanup: delete client if still present.
- Note: `oauth2` group already covers DCR; this one covers the admin surface.

### 7.3 [x] `claim_policy` — per-client / per-key claim policies (M)
- `requires_admin = True`.
- Fixtures: one admin-created OAuth client, one API key.
- Steps:
  1. `GET /api/admin/claim-templates` → non-empty list.
  2. `GET /api/admin/oauth-clients/{client_id}/claim-policy` → returns
     `rules` + `default_rules`.
  3. `PUT .../claim-policy` body `{"rules": [<ClaimRulePayload>]}` → then `GET`
     shows `is_custom=true` and the rule.
  4. `DELETE .../claim-policy` → `GET` shows `is_custom=false`.
  5. same three calls under `/api/admin/api-keys/{key_id}/claim-policy`.
- Gotchas: claim names must be URIs unless they are OIDC-standard; use the
  template's own `claim_name` to stay valid. `PUT` with `rules: []` deletes.

### 7.4 [x] `device_auth` — RFC 8628 device grant (M)
- `requires_admin = True` (cleanup) — the approve step needs an end-user token.
- Steps:
  1. `POST /oauth2/device/authorize` (form: `client_id`, `scope`) → `{device_code,
     user_code, verification_uri, ...}`. Use an existing client (the first-party
     client from `/api/auth/oidc/config`, or register one via DCR).
  2. as a user: `POST /api/oauth2/device/verify {"user_code"}` → device info.
  3. `POST /api/oauth2/device/approve` (body to confirm in router — likely
     `{user_code}`) with the user bearer.
  4. poll `POST /oauth2/token` `grant_type=urn:ietf:params:oauth:grant-type:device_code`
     `device_code=<...>` → access token.
  5. `GET /api/oauth2/device/authorizations`; `POST .../{user_code}/revoke`.
- Gotchas: confirm the exact `approve`/`deny` body in
  `backend/authglow/api/device_auth.py`; endpoints are 30/min.

### 7.5 [x] `user_profile` — self-service account management (S)
- `requires_admin = True` (fixture creation/cleanup).
- Steps (as a fixture user, `ctx.new_client()`):
  1. `GET /api/profile/me`, `PATCH /api/profile/me` (first_name/…).
  2. `GET /api/profile/me/preferences`, `PATCH` a preference.
  3. `POST /api/profile/me/change-password {current_password, new_password}` →
     re-login with the new password.
  4. `POST /api/profile/me/change-email {new_email, password}` → `GET` reflects it.
  5. `POST /api/profile/me/deactivate/challenge` → `POST /api/profile/me/deactivate`
     (body `{challenge_id, word}`) → login rejected (403/401).
  6. re-activate via admin `PUT /api/admin/users/{id}` (`is_active: true`) — the
     self-service `reactivate` endpoint cannot be reached by a deactivated
     caller (known caveat).
  7. `DELETE /api/profile/me {password, confirmation: "DELETE"}` → login fails.
- Cleanup: admin delete (idempotent).
- Gotchas: confirm `deactivate` body in `user_profile.py`; deleting own account
  frees the email so no cleanup may be needed.

### 7.6 [x] `password_reset` — reset + forced change (M, demo inbox for codes)
- `requires_admin = True`.
- Fixtures: a user with a known password.
- Steps:
  1. `POST /api/password/reset/request {"email"}` → 200.
  2. read code from `GET /api/demo/inbox?email=` (demo only) or `ctx.skip` the
     confirmation when not demo.
  3. `POST /api/password/reset/confirm {"reset_code", "new_password"}` → login
     with the new password succeeds.
  4. forced change: admin `POST /api/admin/users/{id}/expire-password` →
     `POST /api/oauth2/authorize` returns `{password_expired: true}` →
     `POST /api/auth/expired-password/change {email, current_password, new_password}`.
- Gotchas: reset request is `5/hour` — one per run. Code regex: the
  human-friendly `reset_code` is 14–20 chars, in the email body.

### 7.7 [x] `email_verification` — verify + resend (S, demo inbox)
- `requires_admin = True`.
- Steps:
  1. create/register a user → welcome email captured.
  2. `GET /api/demo/inbox?email=` → extract code → `POST /api/email/verify {"token": code}`
     → `GET /api/admin/users/{id}` shows `email_verified=true`.
  3. `POST /api/email/resend-verification {"email"}` → 200 (rate limit `3/hour`).
- Non-demo: skip the code-dependent checks with a reason.

### 7.8 [x] `webhooks` — endpoint CRUD + delivery (M, external: receiver)
- `requires_admin = True`.
- Steps:
  1. `POST /api/admin/webhooks {"url": "https://example.com/hook", "events": [<valid event>], "insecure": false}` → 201 with signing secret (once).
  2. list / get / `PATCH` (e.g. `active: false`) / `POST .../{id}/rotate-secret`.
  3. `POST .../{id}/test` — a real signed delivery. Either stand up a tiny
     receiver or use `insecure: true` + `http://127.0.0.1:9` and assert the
     response reports a delivery failure (do not fail the group on it).
  4. `GET .../{id}/deliveries` → entries exist for the test.
  5. `DELETE .../{id}` → 204.
- Gotchas: event names must be in `VALID_EVENT_TYPES` (use the webhook test
  fixtures or read `models/webhook_events.py`); `http` requires `insecure=true`.

### 7.9 [x] `federation` — external IdP config (S, no real IdP)
- `requires_admin = True`.
- Steps:
  1. `POST /api/federation/providers` body `ExternalIdpConfigCreate`
     (`label`, `issuer`, `client_id`, `client_secret`; `issuer` must be an
     `https://` URL).
  2. `GET /api/federation/admin/providers` contains it; `PUT .../{id}` updates
     the label; `PATCH .../{id}/toggle` flips `enabled`.
  3. public `GET /api/federation/providers` lists it only when enabled.
  4. `DELETE .../{id}`.
- Do NOT call `/api/federation/login/{id}` (would redirect to a real IdP).
- Gotchas: `client_secret` is never returned (assert absence, not value).

### 7.10 [x] `sessions` — admin session/token management (S)
- `requires_admin = True`.
- Fixtures: a user with an active login (create → login).
- Steps:
  1. `GET /api/admin/sessions` includes the user's session.
  2. `GET /api/admin/users/{user_id}/sessions`; `POST .../sessions/revoke-all` →
     user's refresh token no longer usable.
  3. `POST /api/admin/tokens/refresh/{token_id}/revoke`.
  4. `POST /api/admin/sessions/cleanup`.
- Note: the user-facing side (list/revoke-all) is already covered by the `auth`
  group; keep this admin-focused.

### 7.11 [x] `consents` — OAuth consent record lifecycle (M)
- `requires_admin = True`.
- Steps:
  1. Drive a full authorization-code flow with a **consent-requiring** client
     (DCR client with `require_consent`, or admin-created) so a consent record
     is created (the `oauth2` group already handles the consent prompt via
     `ApiClient.authorize_code`).
  2. `GET /api/admin/oauth-consents` → the consent appears.
  3. `POST /api/admin/oauth-consents/{consent_id}/revoke` → gone.
- Cleanup: delete the DCR client.

### 7.12 [x] `jwk_keys` — signing-key rotation (M, destructive-ish)
- `requires_admin = True`.
- Steps:
  1. `GET /api/admin/jwk-keys` → keyring info.
  2. `POST /api/admin/jwk-keys/rotate/challenge` → `{challenge_id, word}`.
  3. `POST /api/admin/jwk-keys/rotate {challenge_id, word}` → new active key.
  4. verify `GET /.well-known/jwks.json` now includes the new kid.
  5. `POST /api/admin/jwk-keys/{kid}/revoke` on a **non-active** key only.
- Gotchas: rotating the live signing key is intrusive on a shared instance.
  Guard with `--yes`/confirmation like remote targets, or restrict to revoking
  a just-created key. Never revoke the only active key.

### 7.13 [x] `settings` — runtime settings + rate limits (M, intrusive)
- `requires_admin = True`.
- Steps:
  1. `GET /api/admin/settings`, `GET /api/admin/settings/schema` (schema non-empty).
  2. `PATCH /api/admin/settings` with a field set to its current value (no-op) —
     avoids changing behaviour.
  3. `GET /api/admin/rate-limits`, `GET /api/admin/rate-limits/status`.
  4. `PUT /api/admin/rate-limits/config` with a per-route override, then restore
     the previous config in `finally`.
- Gotchas: never leave global rate limits disabled; snapshot and restore.
  `--relax-rate-limits` in `cli.py` already shows the save/restore pattern.

### 7.14 [x] `par` — Pushed Authorization Requests (S)
- `requires_admin = True` (cleanup) or use the first-party client.
- Steps:
  1. `POST /oauth2/par` (client-authenticated form: `client_id`, `response_type`,
     `redirect_uri`, `scope`, `code_challenge`, `state`) → `{request_uri, ...}`.
  2. `POST /api/oauth2/authorize` with `request_uri` (instead of inline params)
     → code; exchange at `/oauth2/token`.
  3. negative: replay the same `request_uri` → rejected (single-use).

### 7.15 [x] `passkeys` — WebAuthn (S, external: authenticator)
- `requires_admin = True`.
- Only test the local surface: `GET /api/passkey/list` (empty is fine),
  admin `GET /api/admin/users/{id}/passkeys`. `register/complete` and
  `auth/complete` need a real authenticator signature, so `ctx.skip` them with
  an explicit reason ("WebAuthn ceremony requires a browser/authenticator").

### 7.16 [x] `phone_verification` — OTP (S, external: SMS provider)
- `requires_admin = True`.
- Default `PHONE_VERIFICATION_BACKEND=always_allow` generates a random code but
  never returns it, so `POST /api/phone/verify` cannot be completed over HTTP.
  Test `POST /api/phone/request` (200) and `ctx.skip` the verify step.
- Do not burn the `5/hour` budget.

### 7.17 [x] `demo_inbox` — demo-only sandbox affordances (S)
- `requires_admin = False`.
- Guard: read `GET /api/meta`; if `demo_mode` is false, `ctx.skip` the whole
  group. When demo: `GET /api/demo/inbox?email=...` is 200 and returns
  `{"emails": [...]}`; `GET /api/meta` exposes the demo email + password.

### 7.18 [x] `admin_insights` — read-only forensic endpoints (S)
- `requires_admin = True`.
- Fixtures: one user with a login.
- Steps: `GET /api/admin/users/{id}/login-history`, `/security-events`,
  `/oauth-consents`, `/admin-actions`, `/export`, and admin
  `GET /api/admin/users/{id}/passkeys`.
- All read-only; assert 200 and sane shapes (no destructive calls).

---

## 8. Optional (separate task, not a group)

The frontend audit (`checktool/coverage/audit.py`) lists client-side-only
capabilities. The owner chose to **only report** them for now. If you later
implement the backend gaps:

- `POST /api/admin/oauth-clients/{client_id}/preview-claims` (+ api-key
  equivalent) that runs `ClaimPolicyService.build_claims` for a subject/scope
  and returns rendered claims without issuing a token.
- `is_current` flag on `GET /api/tokens/refresh/list` sessions.

These touch `backend/`, which is currently off-limits for this workstream —
coordinate before changing it.

## 9. Suggested session batching

- Session A (low risk, no external deps): `user_profile`, `federation`,
  `claim_policy`, `sessions`, `admin_insights`.
- Session B (needs pyotp / demo inbox): `mfa`, `email_verification`,
  `password_reset`.
- Session C (protocol): `device_auth`, `par`, `consents`, `oauth_clients`.
- Session D (intrusive/external): `webhooks`, `jwk_keys`, `settings`,
  `phone_verification`, `passkeys`, `demo_inbox`.

Do one group per branch, run the §4 definition-of-done, and keep the diff to
`checktool/` only.
