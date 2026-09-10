---
type: plan
status: active
supersedes: rbac-admin-gating-and-system-oauth-client (admin-gating parts)
---

# Plan — Eliminazione scope `admin` → ruolo RBAC "Authglow Administrator"

> **Status**: approved (grill completed). This plan supersedes the
> admin-gating portions of
> `../archive/rbac-admin-gating-and-system-oauth-client.md` where they conflict
> (role name, permission bypass, API-key warning). The system-client
> parts of that plan are NOT in scope here.
>
> **Convention**: every phase and sub-step has a `[ ]` checkbox.
> Mark it `[x]` when done. A phase is "complete" only when ALL its
> checkboxes are checked AND the targeted verification command is
> green. Between Fase 3 and Fase 4 the full suite may be red —
> that is expected; only targeted verification matters there.
>
> **Commits**: NEVER committed automatically. Commit checkpoints are
> listed per phase but executed only on explicit user request.

## Decisions locked (grill)

| # | Decision | Choice |
|---|----------|--------|
| D1 | Admin guard | direct role check, `user_has_role(user_id, ADMIN_ROLE_NAME)` |
| D2 | API keys | follow the owner's RBAC (`is_admin` = owner has the Administrator role); BOPLA filter + warning log stay |
| D3 | Existing data | fresh start — NO data migration; users holding the `admin` scope lose admin access |
| D4 | OAuth scopes | `read`/`write`/`offline_access` remain on users for OAuth2/API-key flows |
| D5 | Role identity | `name = "Authglow Administrator"` (exact string), constant `ADMIN_ROLE_NAME` |
| D6 | Anti-lockout | refuse self-demotion AND any removal that would leave zero Administrators |
| D7 | Scope `admin` | rejected (422) at ingestion via `RESERVED_SCOPE_TOKENS` in `core/scopes.py`; removed from `FIRST_PARTY_OAUTH_SCOPES` |
| D8 | Permission bypass | kept, role-based: Administrator bypasses all `require_permission` checks (`core/permissions.py:82-85` becomes a role check) |
| D9 | Roles UX | role multi-select on invite/create forms + role chips w/ assign/remove in `UserDrawer` |

## Current-state facts (verified)

- `require_admin` (scope-based) is duplicated in 3 files:
  `api/admin.py:89`, `api/oauth_client.py:57`, `api/claim_policy.py:67`;
  imported by `admin_settings.py`, `webhooks.py`, `federation.py`.
- Inline `"admin" (not) in current_user.scopes` checks:
  `api/auth.py:2258` (invite), `api/api_key.py` (~15 sites),
  `api/password_reset.py` (6 sites).
- Scope-based bypass in `PermissionChecker.__call__`
  (`core/permissions.py:82-85`).
- Role-based `require_admin()` = `require_role("admin")` in
  `core/permissions.py:169`; used by `api/rbac.py` routes;
  `api/rbac.py:393` computes `is_admin` via
  `user_has_role(user_id, "admin")`.
- `RBACService.initialize_defaults()` (`services/rbac.py:186`) seeds
  roles `admin`/`user`/`developer` + 11 permissions — **never called
  at startup** (only in tests). GAP: fresh installs have an empty
  RBAC store.
- Bootstrap user: `api/setup.py:112-122` with
  `scopes=["read","write","admin"]`, `is_bootstrap=True`.
- Demo user: `services/demo.py:92-103`, same scopes; existing-user
  path only re-activates + rotates password.
- `/api/users/me` (`api/auth.py:2433`) returns `UserResponse`
  (`models/user.py:110-126`): scopes only, no roles — the frontend
  `AuthUser.roles/permissions` fields are always `undefined` today.
- `services/user_profile.py:104` fills `roles` from scopes (hack).
- Frontend admin gate: `Sidebar.tsx:49`, `DashboardPage.tsx:38` use
  `user?.scopes?.includes('admin')`; `ProfilePage.tsx:241` special-cases
  `scope === 'admin'`; `AdminUsersPage.tsx` invites/creates users with a
  free-text scopes input.
- `FIRST_PARTY_OAUTH_SCOPES` (`services/oauth_client.py:244`) still
  contains `admin`.
- `Role.name` is a free-form string (`models/rbac.py:35`); lookups are
  exact-match via `get_role_by_name`.
- OIDC discovery does NOT advertise `admin`
  (`api/oidc.py:58-62` default scopes list).
- OAuth client `allowed_scopes` does NOT go through
  `validate_scope_tokens` (no validator in `models/oauth_client.py`) —
  the authorization filter (`api/auth.py:1317`) already drops scopes
  the user does not hold.
- Audit enum already has `ADMIN_ROLE_ASSIGNED` / `ADMIN_ROLE_REMOVED`
  (`models/audit_events.py:102-103`) + `AdminRoleMetadata`.

---

## [x] Fase 0 — Pre-flight baseline

- [ ] `cd backend`
- [ ] `rtk ruff check authglow/` — record baseline
- [ ] `rtk pytest tests/unit/test_rbac.py -q` — record baseline
- [ ] `rtk pytest tests/unit/test_setup.py tests/unit/test_demo.py -q`

---

## [x] Fase 1 — Fondamenta RBAC

**Goal**: constant, seeding of the new role, lifespan wiring,
idempotent helpers. No guard behaviour change yet.

### [ ] 1.1 `backend/authglow/core/permissions.py`

- [ ] Add `ADMIN_ROLE_NAME = "Authglow Administrator"` module constant
      (near the top, documented).
- [ ] In `PermissionChecker.__call__` (lines 82-87): replace the
      scope-based bypass with the role-based one. Order matters: the
      check needs `rbac_service`, so move it after instantiation:
      ```python
      rbac_service = RBACService()

      # D8: the Administrator role implies every permission — the
      # role-based successor of the old scope=admin bypass.
      if await rbac_service.user_has_role(user_id, ADMIN_ROLE_NAME):
          return user_id
      ```
- [ ] Rename `require_admin()` (line 169) → `require_administrator()`
      returning `require_role(ADMIN_ROLE_NAME)`; update docstring.
- [ ] Update `api/rbac.py` import (line 7) accordingly.

### [ ] 1.2 `backend/authglow/services/rbac.py`

- [ ] `initialize_defaults()`: seed the system role
      `"Authglow Administrator"` (all default permissions,
      `is_system=True`) **instead of** `"admin"`. Roles `user` and
      `developer` unchanged. Import `ADMIN_ROLE_NAME` from
      `core.permissions`.
- [ ] Append two idempotent helpers:
      - `ensure_admin_role() -> str` — calls
        `initialize_defaults()`, returns the Administrator role id.
      - `assign_role_to_user_idempotent(user_id, role_id, actor_id) -> bool`
        — no-op when already assigned; permanent expiry.
- [ ] Export nothing else; keep the existing surface.

### [ ] 1.3 `backend/main.py` lifespan

- [ ] Call `await RBACService().initialize_defaults()` BEFORE
      `ensure_first_party_client()` and the demo seed (so the
      Administrator role exists before any user is created).
- [ ] Log `RBAC_DEFAULTS_SEEDED` on first creation (info level).

### [ ] 1.4 Tests

- [ ] `backend/tests/unit/test_rbac.py`: update
      `test_initialize_defaults` / `test_initialize_defaults_idempotent`
      to expect `Authglow Administrator` (system) instead of `admin`;
      new tests for `ensure_admin_role` (idempotent, stable id) and
      `assign_role_to_user_idempotent` (second call returns False).

### [ ] 1.5 Verification

- [ ] `rtk pytest tests/unit/test_rbac.py -q`
- [ ] `rtk ruff check authglow/`

**Commit checkpoint** (on request): `feat(rbac): seed Authglow Administrator system role at startup; add idempotent role helpers`

---

## [x] Fase 2 — Bootstrap: setup + demo

**Goal**: the first user and the demo user are born with
`scopes=["read","write"]` + the Administrator role. No admin-scope
anywhere at creation.

### [ ] 2.1 `backend/authglow/api/setup.py`

- [ ] In `create_admin_user`: change `scopes` to `["read", "write"]`
      (line 117).
- [ ] After `create_user`: call `ensure_admin_role()` +
      `assign_role_to_user_idempotent(user.id, role_id, actor_id=user.id)`.
- [ ] Audit `ADMIN_ROLE_ASSIGNED` with `AdminRoleMetadata`
      (`admin_user_id=user.id` — self-assigned by bootstrap).
- [ ] Defensive: the lifespan already seeded defaults; keep a bare
      `ensure_admin_role()` call (idempotent) rather than
      re-running the full seeding.

### [ ] 2.2 `backend/authglow/services/demo.py`

- [ ] Change demo user `scopes` to `["read", "write"]` (line 97).
- [ ] Restructure so BOTH paths (new + existing user) run the
      idempotent role assignment (the demo admin must always hold the
      role — this is what keeps E2E/dev working under D3).
- [ ] Audit `ADMIN_ROLE_ASSIGNED` only when the assignment was newly
      created.

### [ ] 2.3 Tests

- [ ] `backend/tests/unit/test_setup.py`: assert scopes are
      `["read", "write"]`, no `admin`; assert the role assignment
      exists.
- [ ] `backend/tests/unit/test_demo.py`: same assertions for both
      the create path and the existing-user path (idempotent).

### [ ] 2.4 Verification

- [ ] `rtk pytest tests/unit/test_setup.py tests/unit/test_demo.py -q`

**Commit checkpoint**: `feat(bootstrap): first user and demo user get the Authglow Administrator role instead of the admin scope`

---

## [x] Fase 3 — Cutover: reserved scope + unified guard + inline checks

**Goal**: the OAuth `admin` scope stops being an authorization
signal everywhere. **Note**: after this phase and before Fase 4
completes, the full suite is expected red; verify only the files
listed.

### [ ] 3.1 Reserved scope token (D7)

- [ ] `backend/authglow/core/scopes.py`: add
      `RESERVED_SCOPE_TOKENS = frozenset({"admin"})`;
      `validate_scope_tokens` raises `ValueError` listing reserved
      tokens (message: admin authority is RBAC-driven — assign the
      "Authglow Administrator" role instead).
- [ ] `backend/authglow/services/oauth_client.py:244`:
      `FIRST_PARTY_OAUTH_SCOPES = "openid profile email read write offline_access"`.
- [ ] Do NOT touch OAuth client `allowed_scopes` validators (out of
      the choke point by design; the authorization filter protects).

### [ ] 3.2 Unified `require_administrator` (D1)

- [ ] `backend/authglow/api/admin.py`: replace the scope-based
      `require_admin` (line 89) with:
      ```python
      async def require_administrator(current_user: User = Depends(get_current_user)) -> User:
          """Require the caller to hold the Authglow Administrator role.

          Admin gating is RBAC-driven only; the OAuth ``admin`` scope
          is ignored (and rejected at ingestion since D7).
          """
          if not await RBACService().user_has_role(current_user.id, ADMIN_ROLE_NAME):
              raise HTTPException(status_code=403, detail="Admin access required")
          return current_user
      ```
- [ ] Add `async def user_has_admin_role(user_id: str) -> bool` helper
      (thin wrapper over `RBACService().user_has_role`).
- [ ] If importing `api.admin` from `oauth_client.py`/`claim_policy.py`
      creates an import cycle, move the guard to a new
      `backend/authglow/api/deps.py` instead and re-point ALL
      consumers (contingency).
- [ ] Delete the duplicates: `api/oauth_client.py:57`,
      `api/claim_policy.py:67`; re-point imports in
      `admin_settings.py`, `webhooks.py`, `federation.py`,
      `oauth_client.py`, `claim_policy.py`.
- [ ] `core/permissions.py`: `require_administrator()` (role-based,
      returns user_id) stays the dependency for `api/rbac.py` routes —
      now referencing `ADMIN_ROLE_NAME`.

### [ ] 3.3 Inline checks → RBAC (D1, D2)

- [ ] `api/auth.py:2258` (invite): replace the scope check with
      `Depends(require_administrator)`; drop the inline raise and the
      now-unneeded scope logic in the signature.
- [ ] `api/api_key.py`: every
      `if api_key.user_id != current_user.id and "admin" not in current_user.scopes`
      → `... and not await user_has_admin_role(current_user.id)`;
      `is_admin="admin" in current_user.scopes` (2 sites) →
      `is_admin=await user_has_admin_role(current_user.id)`;
      the 4 remaining bare admin checks (lines 421, 445, 466, 480) →
      `Depends(require_administrator)` or the helper, per site.
- [ ] `api/password_reset.py` (6 sites) → same conversion.
- [ ] `api/rbac.py:393` → `user_has_role(user_id, ADMIN_ROLE_NAME)`.
- [ ] Sweep check: `rg '"admin" (not )?in current_user\.scopes' backend/authglow/`
      → 0 hits.

### [ ] 3.4 Targeted verification

- [ ] `rtk ruff check authglow/`
- [ ] `rtk pytest tests/unit/test_permissions.py -q` (update: bypass
      now role-based; add `test_admin_scope_does_not_grant_admin` and
      `test_administrator_role_bypasses_permissions`)
- [ ] The full suite is expected red until Fase 4 completes.

**Commit checkpoint**: `feat(security)!: admin authority is RBAC-only (Authglow Administrator role); admin OAuth scope rejected at ingestion`

---

## [x] Fase 4 — Backend test sweep

**Goal**: full backend suite green. Highest-risk phase — go
file-by-file, re-run after each.

### [ ] 4.1 `backend/tests/conftest.py`

- [ ] `test_user` fixture (line 238): scopes → `["read", "write"]`,
      NO admin role (plain user).
- [ ] New `admin_test_user` fixture: plain user + Administrator role
      via `RBACService().ensure_admin_role()` +
      `assign_role_to_user_idempotent` (uses the `rbac_service`
      fixture, line 361).
- [ ] Ensure the autouse `_override_settings` still isolates the RBAC
      file stores per test (same lru_cache-bypass pattern as the
      user repos: pass `settings=self.settings` through factories).

### [ ] 4.2 File-by-file sweep (update admin-route tests to use
`admin_test_user`; replace `scopes=["read","write","admin"]`
literals with `["read","write"]`)

- [ ] `tests/unit/test_setup.py`, `tests/unit/test_demo.py` (done in
      Fase 2 — re-check)
- [ ] `tests/integration/test_auth_api.py` (3 literals, lines 463,
      537, 626 + invite/admin tests)
- [ ] `tests/integration/test_federation.py` (line 38)
- [ ] `tests/integration/test_admin_api.py`
- [ ] `tests/integration/test_admin_users_update.py` → actually
      `tests/unit/test_admin_users_update.py` (lines 126, 147)
- [ ] `tests/unit/test_api_key.py` (lines 478, 617, 757 — BOPLA
      tests now RBAC-driven)
- [ ] `tests/unit/test_oidc.py` (line 120)
- [ ] `tests/integration/test_rbac_jwt_injection.py`
- [ ] Any file surfaced by
      `rg 'scopes=\["read", "write", "admin"\]|scopes=\["admin"\]' backend/tests/`

### [ ] 4.3 New coverage

- [ ] `test_setup_assigns_administrator_role_to_first_user`
- [ ] `test_admin_scope_rejected_at_ingestion` (UserCreate / Invite /
      APIKeyCreate → 422)
- [ ] `test_require_administrator_403_without_role` /
      `test_require_administrator_200_with_role`

### [ ] 4.4 Verification

- [ ] `rg '"admin" (not )?in current_user\.scopes' backend/` → 0
- [ ] `rg '"read", "write", "admin"' backend/` → 0 (in non-doc code)
- [ ] `rtk pytest -q --tb=line -n auto` (timeout 300s) — GREEN
      (pre-existing failures per AGENTS.md are out of scope: report,
      don't auto-fix)

**Commit checkpoint**: `test(backend): sweep fixtures and tests to the RBAC admin model`

---

## [x] Fase 5 — Profilo e API utente

- [ ] `models/user.py` `UserResponse`: add
      `roles: List[str] = []` and `is_admin: bool = False`.
- [ ] `api/auth.py:2433` `/api/users/me`: populate `roles` (RBAC role
      names) + `is_admin`.
- [ ] `services/user_profile.py:104`: `roles` from
      `RBACService.get_user_roles` (role names) — remove the
      `# Using scopes as roles for now` hack; `scopes` stays OAuth-only.
- [ ] `models/rbac.py:141`: `UserPermissions.is_admin` docstring →
      role-based.
- [ ] Admin create/invite endpoints gain optional `roles: List[str]`
      (validated against existing roles; assigned post-creation with
      audit events) — needed by D9 UX.
- [ ] Tests: `/api/users/me` returns roles/is_admin; admin create
      with roles round-trip.

Verification: targeted test files + `rtk ruff check authglow/`.

**Commit checkpoint**: `feat(api): expose RBAC roles and is_admin on user responses`

---

## [x] Fase 6 — Anti-lockout (D6)

- [ ] `api/rbac.py` `remove_role_from_user` (line 285): when
      `role.name == ADMIN_ROLE_NAME`:
      - refuse (409) if `user_id == current_user_id` (self-demotion);
      - refuse (409) if the removal would leave zero Administrators
        (count remaining holders via `get_user_roles` over an
        assigned list — implement
        `RBACService.list_users_with_role(role_id)` helper).
- [ ] Same guard honoured by any other removal path (grep for
      `remove_role_from_user`).
- [ ] Tests: self-demotion 409; last-admin 409; demotion with a
      second admin 204.

Verification: `rtk pytest tests/unit/test_rbac.py -q` + new tests.

**Commit checkpoint**: `feat(rbac): anti-lockout guards on Administrator role removal`

---

## [x] Fase 7 — Frontend (D9)

### [ ] 7.1 Admin gate

- [ ] `Sidebar.tsx:49`, `DashboardPage.tsx:38` →
      `user?.is_admin === true` (from `/api/users/me`).
- [ ] `ProfilePage.tsx:241`: remove the `scope === 'admin'`
      special-case.
- [ ] `authStore.ts` `AuthUser`: keep `roles`/`permissions`; ensure
      `is_admin` is typed.

### [ ] 7.2 Roles in the Users surface

- [ ] `AdminUsersPage.tsx`: invite/create forms — replace the
      free-text scopes input with a role multi-select (fetch
      `GET /api/rbac/roles`); POST carries `roles`; scopes field
      keeps OAuth values only (no free-text `admin`).
- [ ] `UserDrawer`: role chips (fetch
      `GET /api/rbac/user-roles/{id}`) + assign/remove actions
      (`POST/DELETE /api/rbac/user-roles`) reusing ConfirmDialog for
      remove.
- [ ] Update tests: `AdminUsersPage.test.tsx`,
      `AdminRateLimitsPage.test.tsx`, `AdminSettingsPage.test.tsx`
      (mocks: `scopes: ['read','write']`, `roles`, `is_admin: true`),
      `lib/scopes.test.ts` (example without `admin`).

### [ ] 7.3 Verification

- [ ] `cd frontend`
- [ ] `npm test` (affected files) — GREEN
- [ ] `npm run lint && npm run build` — GREEN

**Commit checkpoint**: `feat(frontend): RBAC-driven admin gate and role management in the Users surface`

---

## [ ] Fase 8 — E2E + docs + full verification

- [ ] `npx playwright test` (chromium + mobile) — the demo admin
      keeps the role via `seed_demo_user`; admin pages remain
      reachable. Known pre-existing E2E failures are out of scope.
- [ ] `frontend/test-e2e-ux.py` — same expectation.
- [ ] `ARCHITECTURE.md`: authorization section — admin = RBAC role
      "Authglow Administrator"; scope `admin` rejected at ingestion.
- [ ] Full backend suite one last time
      (`rtk pytest -q --tb=line -n auto`, timeout 300s).
- [ ] `rtk mypy authglow/` clean.

**Commit checkpoint**: `docs: authorization is RBAC-driven (Authglow Administrator role)`

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Fixture/test sweep breaks admin-route tests between Fase 3 and Fase 4 | **High** | Expected: targeted verification only; full suite at Fase 4. Sweep file-by-file. |
| Dev/E2E data holds users with only the `admin` scope → they lose admin (D3) | High by choice | Fresh-start decision. Demo path re-grants the role; real dev users re-created via setup. |
| Import cycle when centralising the guard in `api/admin.py` | Low | Contingency: new `api/deps.py`, re-point all consumers. |
| `initialize_defaults` was never called at startup — first boot ordering bugs (role missing when demo user is created) | Medium | Fase 1.3 calls it BEFORE `ensure_first_party_client` and demo seed; `ensure_admin_role` is defensive in setup/demo. |
| Token `roles` claims change for downstream consumers (claim policy now emits real role names) | Low | Additive; templates already surfaced in admin UI. |
| Old dev data keeps an orphan system role `admin` | Low | Harmless: never seeded again, never checked. |
| `user_has_role` adds a file-store read per admin request | Low | Admin surface is low-traffic; revisit with a roles claim only if measured. |

## Glossary of changed names

- `require_admin` (scope-based, `api/admin.py:89`,
  `api/oauth_client.py:57`, `api/claim_policy.py:67`) → **removed**;
  replaced by the single role-based `require_administrator`.
- `require_admin()` (role-based, `core/permissions.py:169`) →
  renamed `require_administrator()`; same role-check semantics,
  now `ADMIN_ROLE_NAME`.
- `user_has_admin_role(user_id)` → **new** helper (`api/admin.py`)
  for compound ownership+admin checks.
- `is_admin` param on `create_key`/`update_key`
  (`services/api_key.py`) → semantics: owner's RBAC, not scopes.
  BOPLA filter and warning log unchanged.
- `"admin"` scope token → **reserved**: rejected at ingestion
  (D7); no longer consulted by any guard.
---

## Addendum — allargamento rate limit (richiesta utente, post-Fase 8)

I limiti default erano troppo stretti per demo/E2E. Pass raise-only su
`@limiter.limit` (nessun limite abbassato); **restano stretti by design**
i vettori d'abuso: \mail_verification.py\ (invio mail), \password_reset.py(reset-code flows), \setup.py\ (brute force setup token).

Tabella: 3/min→10, 5/min→20, 10/min→30, 20/min→60, 30/min→60, 60/min→120,
10/h→60, 20/h→60, 30/h→120, 60/h→120, 10/day→60. Esempi notevoli:
authorize 10/min→30/min, API-key create 10/h→60/h, rotate-secret 10/day→60/day.

Test aggiornati: \	est_federation.py::TestVapt026FederationRateLimits(loop su nuovi limiti: 120/20/30). Verifica: 2644 passed / 7 failed
(tutti pre-esistenti confermati su baseline pristine).

---

## Addendum - riparazione test pre-esistenti (richiesta utente)

Lot 1 backend (7 fallimenti -> 2651 passed, 0 failed): fix BUG REALE ClientCredentialsMetadata/client_auth_method in token_endpoint; mock aggiornati ai metadata Pydantic strict (offline, revoke, prompt, basic_auth); fixture autouse _reset_shared_caches contro il flake della cache oauth_client sotto -n auto.

Lot 2 E2E (13 fallimenti -> 44 passed, 0 failed): helper al flusso OAuth2+PKCE reale; password demo da /api/meta; helper CSRF con re-fetch dopo ogni navigazione (i token ruotano); wizard client a 4 step; success screen create raggiungibile (fix BUG: handleCreate chiudeva il modal con la success dentro); RevocationFlow ora invia le credenziali client (fix BUG RFC 7009 401); route mock federation con glob; selettori mobile (:visible, select flow, backdrop position); nomi univoci anti-409; nuovi testid. Rate limit allargati raise-only (strict solo email/reset/setup).

---

## Addendum - 7 permessi UX con enforcement (P0-P3)

Vocabolario: users/sessions/clients/keys/system/roles .manage + admin.read (+ roles.read legacy). Administrator con tutti gli 8; backfill idempotente anti-lockout upgrade. Enforcement rotta-per-rotta (scritture = manage esatto, letture = any(manage, admin.read)); helper user_has_permission/user_has_any_permission + require_user_with_permission (User-returning). Bypass D8 mantenuto. Frontend: permissions in /api/users/me, Sidebar per-sezione, Dashboard stats su admin.read. Proof: tests/integration/test_permission_enforcement.py (13 test allow/deny per Support/Auditor/plain/Administrator). Verifica: backend 2651+14=2665/0, frontend 515, E2E 44/0.

---

## Addendum - rimozione bypass D8 (verificata)

Il bypass Administrator in PermissionChecker e rimosso: ogni chiamata passa solo per permessi/ruoli detenuti esplicitamente. Administrator passa ovunque perche detiene tutto il vocabolario (seed + backfill). Prova empirica: backend 2666/0 + E2E live 44/0 SENZA bypass. Test aggiornati: role-alone-denied + explicit-grant (test_permissions.py).
