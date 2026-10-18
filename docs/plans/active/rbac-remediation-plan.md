---
type: plan
status: active
ids: RBAC-NNN
---

# RBAC Remediation Plan (review 2026-10-18)

> **Status**: Wave 1 completed ✅ | Wave 2 blocked on D1–D3 decisions.
> **Source**: theme review "RBAC" (`authglow-review` skill) over `models/rbac.py`,
> `services/rbac.py`, `api/rbac.py`, `core/permissions.py`, `repositories/file/rbac.py`,
> the admin/oauth/claims/federation/webhooks routers, the frontend admin gate, and
> `docs/plans/active/vapt-fix-plan.md`.
> **Scope reviewed at**: working tree clean, commit `afd9920`.
> **Findings**: 15 (1 Blocker, 4 High, 5 Medium, 4 Low, 1 Info), mapped below as
> `Review finding R<n>`.

## How to use this file

Stable IDs `RBAC-NN`. One task = one commit, smallest safe change first. Tick
`[ ]` → `[x]` with the commit SHA when done. Tasks marked **blocked** need a
decision from the owner before work starts (see [Decisions](#decisions-required-before-start)).

Cross-cutting rules:

- Backend: after each task run only the touched test files, then the full suite
  once per wave (`pytest -q --tb=line -n auto`, Bash `timeout: 300000`).
- Do not touch `backend/tests/conftest.py`. New fixtures live in the test file
  that uses them and pass `settings=` explicitly to every service/repository ctor
  (lru_cache isolation, see `AGENTS.md`).
- Behaviour changes carry their doc update in the same commit
  (`ARCHITECTURE.md`, `docs/reference/features.md`, and the trackers below).
- Pre-existing test failures: report, do not fix without asking.

## Summary

| ID | Wave | Severity | Area | Review finding |
|----|------|----------|------|----------------|
| RBAC-01 | 1 | Blocker | Correctness / authorization path | R1 — naive `expires_at` → 500 |
| RBAC-02 | 1 | Low | Lint | R11 — `ruff format` on the two RBAC modules |
| RBAC-03 | 2 | High | Security | R4 — account state not revalidated |
| RBAC-04 | 2 | High | Security | R3 — `roles.manage` self-escalation |
| RBAC-05 | 2 | High | Standards (audit) | R5 — no audit on role/permission mutations |
| RBAC-06 | 2 | Medium | Data integrity | R6 — deleting an in-use permission |
| RBAC-07 | 2 | High | OAuth2/OIDC | R2 — any-audience token on internal surfaces |
| RBAC-08 | 2 | Medium | Security | R8 — no rate limit on RBAC endpoints |
| RBAC-09 | 3 | Info | Tests | R15 — source-string "escalation" tests |
| RBAC-10 | 3 | Low | Audit data quality | R12 — user id passed as email |
| RBAC-11 | 3 | Medium | Performance | R7 — full-directory scan per check |
| RBAC-12 | 3 | Medium | Docs | R9 — `features.md` §11 stale |
| RBAC-13 | 3 | Low | Frontend | R13 — no permission-based route guard |
| RBAC-14 | 3 | Info | Standards | R14 — two `require_administrator` definitions |

---

## Wave 1 — Unblock (no decision required)

### [ ] RBAC-01 — Normalise `expires_at` to UTC
- **Review finding**: R1 (Blocker).
- **Goal**: remove the `TypeError` that breaks every authorized request for a user
  holding an expiring role assignment.
- **Files**: `backend/authglow/models/rbac.py`,
  `backend/authglow/repositories/file/rbac.py`,
  `frontend/src/pages/admin/AdminRbacPage.tsx`.
- **Change**
  1. `models/rbac.py`: `field_validator` on `AssignRoleRequest.expires_at` and
     `UserRole.expires_at` — if the value is naive, assume UTC
     (`replace(tzinfo=timezone.utc)`). Do **not** raise: existing on-disk
     documents must stay readable.
  2. `repositories/file/rbac.py:240` and `:266`: normalise before comparing via a
     shared `_as_utc(dt)` helper.
  3. `AdminRbacPage.tsx:534`: send `new Date(expiresAt).toISOString()` instead of
     the raw `type="date"` value (semantics per decision D4).
- **Tests**: in `backend/tests/unit/repositories/file/test_rbac.py` — assign with
  `expires_at="2026-01-01"` → `list_for_user` does not raise and treats the
  assignment as expired.
- **Verify**: `pytest -q --tb=line tests/unit/repositories/file/test_rbac.py tests/unit/test_rbac.py`
  and `npm test -- src/pages/admin/AdminRbacPage.test.tsx`.
- **Done when**: the review repro (`ur.expires_at < utcnow()` with a naive value)
  no longer raises, and a previously poisoned file becomes readable again.
- **Risk**: low; only the meaning of a date-only input is at stake (D4).

### [x] RBAC-02 — `ruff format` the RBAC modules ✅ a5d762b
- **Review finding**: R11.
- **Files**: `backend/authglow/api/rbac.py`, `backend/authglow/services/rbac.py`
  ("2 files would be reformatted"). Repo-wide there are 31 unformatted files —
  **do not** widen this task; open a separate one if desired.
- **Changes**:
  - `api/rbac.py`: wrapped long function signatures with default arguments on
    new lines (6 places).
  - `services/rbac.py`: collapsed multi-line signature to single line for
    the three-parameter `user_has_any_permission` method.
- **Verify**: `python -m ruff format --check authglow/api/rbac.py authglow/services/rbac.py`
  clean; `ruff check` unchanged (already clean).
- **Note**: RBAC-09 replaces the `inspect.getsource` tests that this formatting
  touches.

---

## Wave 2 — Security (blocked on D1–D3)

### [ ] RBAC-03 — Enforce account state in authorization (blocked: D3)
- **Review finding**: R4 (High).
- **Goal**: an inactive or suspended user no longer authorizes.
- **Files**: `backend/authglow/core/permissions.py`,
  `backend/authglow/api/admin.py` (suspend path),
  `backend/tests/unit/test_permissions.py`,
  `backend/tests/integration/test_admin_api.py`.
- **Change**
  1. `PermissionChecker.__call__` and `core.permissions.get_current_user`:
     resolve the user's state through the user repository (explicit `settings=`
     for test isolation) and reject with 401/403 when `is_active` is false or
     `suspended_until > utcnow()`.
  2. `suspend_user` (`api/admin.py:1751`): revoke the target's refresh tokens and
     blacklist live access tokens, reusing the `RefreshTokenService.revoke_user_tokens`
     + blacklist pattern already used by password reset and MFA verification.
- **Tests**: behaviour, not source — inactive user with a valid token → 401;
  suspended user → 403; admin suspension invalidates the next request.
- **Done when**: `core.permissions` surfaces reject inactive/suspended users and
  suspension takes effect without waiting for token expiry.
- **Open question**: D3 (does suspension revoke sessions, or only block new logins?).

### [ ] RBAC-04 — Close the `roles.manage` self-escalation (blocked: D1)
- **Review finding**: R3 (High).
- **Goal**: a `roles.manage` holder cannot grant themselves the
  `Authglow Administrator` role, nor a role carrying `roles.manage`.
- **Files**: `backend/authglow/api/rbac.py`,
  `backend/authglow/services/rbac.py`, `backend/tests/unit/test_rbac.py`.
- **Change**: in `assign_role_to_user` (`api/rbac.py:225-261`), after loading the
  role, if `role.name == ADMIN_ROLE_NAME` require
  `user_has_admin_role(current_user_id)` → otherwise 403. Recommended extra:
  refuse self-assignment of any role whose permission list contains
  `roles.manage`.
- **Tests**: rewrite `tests/unit/test_rbac.py:508-564` (7 `inspect.getsource`
  asserts) as behaviour: actor with only `roles.manage` → 403 on assigning the
  Administrator role; Administrator → 201. This is also RBAC-09.
- **Done when**: the Administrator role cannot be granted without already holding
  it, and `vapt-fix-plan.md:71-76` (VAPT-006/007/008) is consistent with the code
  again.
- **If D1 = "delegation is intentional"**: skip the code change, document the
  delegation in `ARCHITECTURE.md` + `features.md`, and close the three VAPT items
  as accepted risk. Do not leave the contradiction in place.

### [ ] RBAC-05 — Audit events for RBAC mutations
- **Review finding**: R5 (High; `AGENTS.md` requires audit on role/scope changes).
- **Files**: `backend/authglow/models/audit_events.py`,
  `backend/authglow/models/audit_metadata.py`, `backend/authglow/api/rbac.py`,
  `backend/tests/unit/test_rbac_api.py`.
- **Change**: add `ADMIN_ROLE_CREATED`, `ADMIN_ROLE_UPDATED`, `ADMIN_ROLE_DELETED`,
  `ADMIN_PERMISSION_CREATED`, `ADMIN_PERMISSION_DELETED` and emit them from
  `create_permission` (`:43`), `delete_permission` (`:93`), `create_role` (`:106`),
  `update_role` (`:166`), `delete_role` (`:210`), with the real `admin_user_id`
  and the affected `role`/`target_user_id` where applicable.
- **Tests**: unit with a mocked `AuditService`, asserting `event_type` and the
  required metadata fields (see `AGENTS.md` → Testing Audit Events).
- **Note**: fix the `admin_user_email_hash`-holds-a-UUID issue (RBAC-10) in this
  same commit if convenient.

### [ ] RBAC-06 — Reject deleting an in-use permission
- **Review finding**: R6 (Medium).
- **Files**: `backend/authglow/services/rbac.py` (or `api/rbac.py:93-100`), tests.
- **Change**: before deleting, scan the roles; if referenced → 409 listing the
  roles. Alternative (if delete must succeed): remove the name from every role in
  the same locked operation.
- **Tests**: referenced permission → 409; free permission → 204.
- **Done when**: no dangling permission names remain, so
  `GET /api/rbac/roles/{id}` no longer silently drops unresolvable entries.

### [ ] RBAC-07 — Restrict the internal audience (blocked: D2)
- **Review finding**: R2 (High; OA-505 in the current code comments).
- **Files**: `backend/authglow/core/permissions.py` (`_require_audience`),
  `backend/authglow/api/admin.py`, `backend/tests/unit/test_permissions.py`.
- **Change**: introduce `INTERNAL_AUDIENCE = "authglow-internal"` and replace the
  presence-only check with an equality check on the internal surfaces
  (`/api/admin/*`, `/api/rbac/*`), leaving external resource-server behaviour
  untouched.
- **Tests**: turn `tests/unit/test_permissions.py:341`
  (`test_checker_accepts_any_aud_value`) into a denial case and rename it.
- **Done when**: a token minted for a third-party client cannot reach admin/RBAC
  endpoints.
- **If D2 = "defer"**: the task shrinks to renaming the existing test so it states
  the accepted risk, plus a tracker entry. Do not leave it undocumented.

### [ ] RBAC-08 — Rate limit the RBAC endpoints
- **Review finding**: R8 (Medium; already tracked as VAPT-075, still open).
- **Files**: `backend/authglow/api/rbac.py` (import `limiter` as in
  `api/admin.py:15`).
- **Change**: `@limiter.limit("30/minute")` on the five write endpoints,
  `"60/minute"` on reads; `request: Request` as first parameter where slowapi
  requires it.
- **Done when**: the module matches the rest of the admin routers and the RBAC
  part of the VAPT-075 line is updated.

---

## Wave 3 — Hygiene

### [ ] RBAC-09 — Behavioural tests instead of source assertions
- **Review finding**: R15 (Info) — overlaps RBAC-04.
- **Files**: `backend/tests/unit/test_rbac.py:508-564`.
- **Change**: drop `inspect.getsource`; cover allow/deny through
  `require_permission`/`PermissionChecker` with a real user fixture.

### [ ] RBAC-10 — Correct audit metadata
- **Review finding**: R12 (Low).
- **Files**: `backend/authglow/api/rbac.py:267,272,336,341`.
- **Change**: resolve the actor's email once; stop passing `current_user_id` in
  `email` and `admin_user_email_hash`.
- **Verify**: unit test asserting the audit entry's actor email is not a UUID.

### [ ] RBAC-11 — Cache the permission lookup
- **Review finding**: R7 (Medium).
- **Files**: `backend/authglow/services/rbac.py`,
  `backend/authglow/repositories/file/rbac.py`, tests.
- **Change**: `cachetools.TTLCache` keyed by `user_id` for
  `get_user_permissions`, invalidated on assign/remove; move expired-assignment
  deletion out of the read path (cleanup job or delete-on-write).
- **Tests**: cache hit and invalidation; no timing tests.
- **Done when**: one permission check no longer scans the whole assignment
  directory twice in the same request.

### [ ] RBAC-12 — Documentation
- **Review finding**: R9 + R10 (Medium) — see also `features.md:664-688`,
  `vapt-fix-plan.md:466,638-641`.
- **Files**: `docs/reference/features.md`, `docs/plans/active/vapt-fix-plan.md`,
  `ARCHITECTURE.md`.
- **Change**: real vocabulary (`*.manage` + `admin.read` + legacy `roles.read`),
  drop the non-existent `require_admin()` and the `users.read`/`roles.write`
  examples, document the anti-lockout guards and the D1 outcome; re-verify the
  VAPT-105 description and the VAPT-075 line list.
- **Note**: close in the same commit as RBAC-04 when D1 = "intentional".

### [ ] RBAC-13 — Permission-based route guard in the frontend
- **Review finding**: R13 (Low).
- **Files**: `frontend/src/App.tsx` (`ProtectedRoute` at `:92` or a new
  `RequirePermission`), `frontend/src/pages/admin/AdminRbacPage.tsx`, vitest.
- **Change**: wrap the `/admin/*` block in a guard based on
  `is_admin || permissions.includes('admin.read') || permissions.includes('<area>.manage')`
  with a redirect to `/dashboard`; the server 403 stays authoritative.
- **Done when**: the mutation UI is not mounted for a user without permissions,
  and the guard has a test (mirroring `Sidebar.test.tsx`).

### [ ] RBAC-14 — Consolidate the admin gates
- **Review finding**: R14 (Info).
- **Files**: `backend/authglow/core/permissions.py:175-192`,
  `backend/authglow/api/admin.py:95`.
- **Change**: keep a single `require_administrator`; either use `require_role` in
  `admin.py` (it is currently production-dead) or remove it.
- **Verify**: `mypy` clean; `test_admin_api_coverage.py::test_require_administrator_*`
  updated.

---

## Decisions required before start

| ID | Decision | Proposed default | Blocks |
|----|----------|------------------|--------|
| D1 | May a `roles.manage` holder grant the `Authglow Administrator` role? | No — RBAC-04 returns 403 unless already an Administrator | RBAC-04, RBAC-12 |
| D2 | Handle R2/OA-505 now, or accept the risk? | Now — the surface is admin-only and the change is small | RBAC-07 |
| D3 | Does suspension revoke live sessions? | Yes — RBAC-03 step 2 | RBAC-03 |
| D4 | `type="date"` `expires_at`: midnight UTC or end of day UTC? | End of day UTC, computed in the frontend, sent as ISO | RBAC-01 |

## Non-goals

- Repo-wide `ruff format` (31 files) — separate task.
- Moving the RBAC repositories to a non-file backend.
- New RBAC features (per-API-key scopes, temporary delegations, role hierarchies).

## Commit sequence

1. `fix(rbac): normalise expires_at to UTC` — RBAC-01
2. `style(rbac): ruff format` — RBAC-02
3. `feat(rbac): enforce account state in authorization checks` — RBAC-03
4. `fix(rbac)!: only administrators may grant the Administrator role` — RBAC-04 (breaking)
5. `feat(audit): RBAC role/permission mutation events` — RBAC-05
6. `fix(rbac): reject deleting an in-use permission` — RBAC-06
7. `fix(security): restrict internal audiences` — RBAC-07
8. `feat(rbac): rate limit RBAC endpoints` — RBAC-08
9. hygiene: RBAC-09 … RBAC-14

Suggested branch naming: `fix/rbac-<nn>-<slug>` per task (or one branch per wave).

## Acceptance criteria

- `pytest -q --tb=line -n auto` — no regression beyond the known pre-existing
  failures (report those, do not fix them unasked).
- `ruff check` and `ruff format --check` clean on `authglow/api/rbac.py`,
  `authglow/services/rbac.py`, `authglow/core/permissions.py`,
  `authglow/models/rbac.py`, `authglow/repositories/file/rbac.py`.
- `mypy` clean on those modules; `npm run lint` clean; admin-page vitest green.
- Every one of R1–R8 either closed by a task here or explicitly accepted in this
  file with a rationale under D1/D2.

## Review evidence (not re-run here)

Checks executed during the review: `ruff check authglow/` (clean),
`ruff format --check` (31 files repo-wide, 2 in scope), `mypy` on the five RBAC
modules (clean), `pytest` on the six RBAC test files (161 passed), `npm run lint`
(clean), `vitest` on `AdminRbacPage` / `Sidebar` / `AdminUsersPage` (84 passed),
plus a local Python repro of the naive-datetime comparison (RBAC-01).
Not run: frontend `npm run build` (writes artifacts), Playwright E2E (needs a live
server), coverage measurement.
