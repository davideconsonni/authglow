# Plan — RBAC-driven admin gating + system OAuth client bootstrap

> **Status**: working tree is clean (rollback complete). This plan
> replaces a half-implemented attempt and is meant to be processed
> piece by piece by a fresh agent. Each phase is self-contained and
> ends with a green test run.
>
> **Convention**: every phase and sub-step has a `[ ]` checkbox.
> Mark it `[x]` when done. A phase is "complete" only when ALL its
> checkboxes are checked AND the verification command exits green.

## Context

The platform uses the OAuth `admin` scope as the admin gate across
~30 endpoints. This is a security weakness: any user can be created
with `scopes=["admin"]`, any API key can be minted with that scope,
any OAuth client can be configured with `admin` in its
`allowed_scopes`. The `require_admin` dependency in
`core/permissions.py` had a silent bypass at
`core/permissions.py:82-85` (the bypass was the only thing keeping
the legacy flow working; we are removing it):

```python
scopes = token_data.scopes or []
if "admin" in scopes:
    return user_id  # ← bypasses RBAC entirely
```

The bootstrap admin user is created with
`scopes=["read", "write", "admin"]` in `api/setup.py:117` and the
demo user gets the same in `services/demo.py:97`. The `admin` scope
is meaningless as a security boundary; admin authority must come
from the `admin` RBAC role.

The user wants:

1. A **system OAuth client** created at app setup, with a
   non-deletable flag (`is_system=true`) and a default claim policy
   that fills `https://authglow.example.com/claims/roles` and
   `.../permissions` from the user's RBAC assignments at issue time.
2. The system client is **editable in the admin UI** (the Claims
   tab works like any other client) but its delete button is
   disabled.
3. The `admin` OAuth scope is **no longer an admin gate**. Admin is
   purely RBAC-driven.
4. The bootstrap orchestrator also creates the `admin` RBAC role
   and assigns it to the bootstrap user.
5. The `admin` scope is a normal OAuth scope value (no special
   treatment anywhere). The `is_admin` warning log in
   `services/api_key.py` is removed.
6. API key `admin` scope is allowed but does not make the key
   admin.

## Architectural decisions (locked)

- **System client identity**: the same client the frontend uses to
  log in (`settings.oauth2_client_id`). The bootstrap creates a DB
  record for it. The `aud` and `azp` claims in tokens remain
  `settings.oauth2_client_id`.
- **First-party tokens go through the system client's claim
  policy**: change `client_id=None` →
  `client_id=settings.oauth2_client_id` in cookie refresh /
  cookie-based flow build_claims calls. The system client's claim
  policy is consulted (REPLACE semantic, so the first-party
  `.../default_rules()` are replaced by the explicit policy seeded
  at bootstrap).
- **System client is the only one allowed to set `client_id=None`
  fallback** to the default rules. All other code paths in
  `build_claims` keep the existing semantics.
- **Bootstrap is idempotent**: every helper is safe to re-run on a
  half-populated disk.
- **No migration script**: brute transition, greenfield assumption
  (the operator wipes the DB and re-runs setup).
- **No demo-user backdoor via `admin` scope**: the demo user is
  granted the `admin` RBAC role at boot, not the OAuth scope.

---

## [ ] Phase 0 — Pre-flight check

- [ ] `cd backend`
- [ ] `rtk ruff check authglow/ 2>&1 | head -5` — record baseline
- [ ] `rtk pytest tests/integration/test_api_key_claim_policy.py -q`
- [ ] `rtk pytest tests/integration/test_rbac_jwt_injection.py -q`

Record the baseline so subsequent phases can compare.

---

## [ ] Phase 1 — `is_system` field on `OAuth2Client` + DELETE refused for system clients

**Goal**: add the data-model primitive. No behaviour change yet for
existing tests (the `is_system` field defaults to `False` everywhere
except the system client we will create in Phase 4).

### [ ] 1.1 Model — `../../backend/authglow/models/oauth_client.py`

- [ ] Add `is_system: bool = False` to `OAuth2Client` (line 139,
      after the `dpop_bound` field at line 200). Docstring: "System
      clients are created at bootstrap by the platform (not via the
      admin API) and cannot be deleted via the DELETE endpoint. The
      flag is set at creation time only — the admin UPDATE path
      does not accept a value for this field. The bootstrap
      orchestrator marks the OAuth client backing the first-party
      login flow (settings.oauth2_client_id) so the platform has
      at least one always-present client to authenticate users
      against, regardless of how the admin shapes the surrounding
      OAuth topology."
- [ ] Add `is_system: bool = False` to `OAuth2ClientResponse`
      (line 419, after `dpop_bound`).
- [ ] Do NOT add `is_system` to `OAuth2ClientUpdate` — the field
      is immutable post-creation.
- [ ] Update `_client_response_from_model` (line 461) to pass
      `is_system=client.is_system` into the response.

### [ ] 1.2 Repository — `../../backend/authglow/repositories/file/oauth_client.py`

- [ ] No code change needed: `model_dump(mode="json")`
      round-trips the field automatically.

### [ ] 1.3 Service — `../../backend/authglow/services/oauth_client.py`

- [ ] No code change needed.

### [ ] 1.4 API — `../../backend/authglow/api/oauth_client.py`

- [ ] In `delete_oauth_client` (line 214), after the `not client`
      404 check, insert the system-client guard:
      ```python
      if client.is_system:
          await audit_service.log_event(
              event_type="oauth_client_delete_blocked",
              user_id=current_user.id,
              email=current_user.email,
              metadata={
                  "client_id": client_id,
                  "client_name": client.client_name,
                  "reason": "system_client",
              },
              severity="warning",
          )
          raise HTTPException(
              status_code=status.HTTP_403_FORBIDDEN,
              detail="System OAuth2 clients cannot be deleted.",
          )
      ```
- [ ] Update-only endpoints stay open: an admin can still edit
      the system client's redirect URIs / allowed scopes / display
      name. They just cannot delete it.

### [ ] 1.5 Tests

- [ ] `../../backend/tests/unit/test_oauth_client_model.py` (or
      equivalent): round-trip a client with `is_system=True`,
      ensure the field survives `model_dump(mode="json")` +
      `OAuth2Client(**data)`.
- [ ] `backend/tests/integration/test_oauth_client.py`: new test
      `test_delete_system_client_refused_with_403`. Setup: create a
      client with `is_system=True`, DELETE → expect 403. The
      pre-existing test that creates clients should also still
      pass.

### [ ] 1.6 Verification

- [ ] `rtk ruff check authglow/ tests/`
- [ ] `rtk pytest tests/integration/test_oauth_client.py -q`
- [ ] `rtk pytest tests/unit/test_oauth_client_model.py -q`

**Commit**: `feat(rbac): add is_system field to OAuth2Client and
block DELETE for system clients`

---

## [ ] Phase 2 — RBAC helpers: `ensure_admin_role` and `assign_role_to_user_idempotent`

**Goal**: idempotent bootstrap helpers for the `admin` RBAC role.
No behaviour change yet (helpers only, not called).

### [ ] 2.1 `../../backend/authglow/services/rbac.py`

- [ ] Append two methods to `RBACService` (after
      `initialize_defaults` at line 186-297):
      ```python
      async def ensure_admin_role(self) -> str:
          """Return the ``admin`` role id, creating the role if missing.

          Calls :meth:`initialize_defaults` first so the admin role is
          guaranteed to carry the full permission catalog. Idempotent.
          """
          await self.initialize_defaults()
          role = await self.get_role_by_name("admin")
          if role is None:
              role = Role(
                  name="admin",
                  description="Full system access",
                  permissions=[],
                  is_system=True,
              )
              await self.create_role(role)
          return role.role_id

      async def assign_role_to_user_idempotent(
          self, user_id: str, role_id: str, actor_id: str
      ) -> bool:
          """Assign *role_id* to *user_id* if not already assigned.

          Returns ``True`` if a new assignment was created, ``False`` if
          the user already held the role. The expiration is left as
          ``None`` (permanent).
          """
          existing = await self._user_role_repo.list_for_user(user_id)
          for ur in existing:
              if ur.role_id == role_id:
                  return False
          await self.assign_role_to_user(
              UserRole(
                  user_id=user_id,
                  role_id=role_id,
                  assigned_by=actor_id,
              )
          )
          return True
      ```

### [ ] 2.2 Tests

- [ ] `../../backend/tests/unit/test_rbac.py` (or equivalent): new tests
- [ ] `test_ensure_admin_role_idempotent` — call twice, second
      call is a no-op, role id is stable.
- [ ] `test_ensure_admin_role_creates_with_all_permissions` —
      confirm the returned role has all 12 default permissions.
- [ ] `test_assign_role_to_user_idempotent` — assign once, second
      call returns `False`. Assign two different roles, both are
      kept.

### [ ] 2.3 Verification

- [ ] `rtk pytest tests/unit/test_rbac.py -q`

**Commit**: `feat(rbac): add ensure_admin_role and
assign_role_to_user_idempotent helpers`

---

## [ ] Phase 3 — `ensure_system_oauth_client` + `ensure_system_client_policy`

**Goal**: two idempotent bootstrap helpers. No behaviour change yet
(not called).

### [ ] 3.1 `../../backend/authglow/services/oauth_client.py`

- [ ] Append after the `_default_repository` function (line 233):
      ```python
      async def ensure_system_oauth_client(
          storage: OAuth2ClientStorage,
          settings: Settings,
      ) -> Optional[OAuth2Client]:
          """Make sure a DB record exists for ``settings.oauth2_client_id``.

          Returns the existing or freshly-created :class:`OAuth2Client`.
          Returns ``None`` only if a programmer error skips the
          pre-condition checks — the function never returns ``None``
          for an otherwise-healthy state.

          The bootstrap client gets:
          * ``is_system=True`` (cannot be deleted via the admin API);
          * the platform's ``oauth2_first_party_redirect_uri`` as the
            only ``redirect_uris`` entry, plus common dev ports
            (``http://localhost:{3000,5173,6060,8080}/auth/callback``)
            for dev convenience;
          * ``authorization_code`` + ``refresh_token`` grants;
          * a typical OAuth scope set (``openid profile email`` + the
            standard ``read``/``write``/``offline_access``);
          * ``is_confidential=True``, ``require_pkce=True``,
            ``require_consent=True``;
          * a freshly generated bcrypt hash of
            ``settings.oauth2_client_secret``. The plaintext secret
            is NOT stored — it lives only in the operator's
            environment, like the bootstrap JWT signing key.
          """
          client_id = settings.oauth2_client_id
          existing = await storage.get_client(client_id)
          if existing is not None:
              return existing

          plaintext_secret = settings.oauth2_client_secret.get_secret_value()
          redirect_uris = [settings.oauth2_first_party_redirect_uri]
          for origin in (
              "http://localhost:3000",
              "http://localhost:5173",
              "http://localhost:6060",
              "http://localhost:8080",
          ):
              candidate = f"{origin}/auth/callback"
              if candidate not in redirect_uris:
                  redirect_uris.append(candidate)

          client = OAuth2Client(
              client_id=client_id,
              client_secret="",  # placeholder; storage.create_client hashes the real one
              client_name="AuthGlow System Client",
              description=(
                  "Bootstrap-created OAuth client backing the first-party "
                  "login flow. Cannot be deleted (is_system=true)."
              ),
              redirect_uris=redirect_uris,
              allowed_scopes=[
                  "openid", "profile", "email",
                  "read", "write", "offline_access",
              ],
              grant_types=["authorization_code", "refresh_token"],
              is_confidential=True,
              require_pkce=True,
              require_consent=True,
              is_active=True,
              is_system=True,
          )
          await storage.create_client(client, plaintext_secret)
          return client
      ```

### [ ] 3.2 `../../backend/authglow/services/claim_policy.py`

- [ ] Insert after `build_claims` (around line 258, before the
      "Write path" section header):
      ```python
      async def ensure_system_client_policy(
          self, client_id: str
      ) -> ClientClaimPolicy:
          """Persist a default claim policy for the system OAuth client.

          The system client gets two rules wired to RBAC so that
          issued access tokens carry the namespaced ``.../roles``
          and ``.../permissions`` claims, populated from the user's
          RBAC assignments at issue time. The admin can customise
          the policy via the UI afterwards; the bootstrap only
          seeds an opinionated starting point.

          Idempotent: if a policy already exists for *client_id*,
          this returns it unchanged.
          """
          existing = await self._repository.get_by_client(client_id)
          if existing is not None:
              return existing
          ns = self.settings.claim_namespace.rstrip("/")
          policy = ClientClaimPolicy(
              client_id=client_id,
              rules=[
                  ClaimRule(
                      claim_name=f"{ns}/roles",
                      source=ClaimSource.RBAC_ROLES,
                      include_in=[ClaimTarget.ACCESS_TOKEN, ClaimTarget.ID_TOKEN],
                      description=None,
                  ),
                  ClaimRule(
                      claim_name=f"{ns}/permissions",
                      source=ClaimSource.RBAC_PERMISSIONS,
                      include_in=[ClaimTarget.ACCESS_TOKEN, ClaimTarget.ID_TOKEN],
                      description=None,
                  ),
              ],
          )
          await self.save_policy(policy)
          return policy
      ```

### [ ] 3.3 Tests

- [ ] `../../backend/tests/unit/test_claim_policy.py`: new test
      `test_ensure_system_client_policy_idempotent`.
- [ ] `backend/tests/integration/test_oauth_client.py`: new test
      `test_ensure_system_oauth_client_creates_record_with_is_system`.

### [ ] 3.4 Verification

- [ ] `rtk pytest tests/unit/test_claim_policy.py -q`
- [ ] `rtk pytest tests/integration/test_oauth_client.py -q`

**Commit**: `feat(bootstrap): add ensure_system_oauth_client and
ensure_system_client_policy helpers`

---

## [ ] Phase 4 — Wire the bootstrap into `setup.py` and `demo.py`

**Goal**: end-to-end bootstrap. Wiping the DB and running setup
creates the admin user, the `admin` RBAC role, the system OAuth
client, and the system client's claim policy, all idempotently.

### [ ] 4.1 `../../backend/authglow/api/setup.py`

- [ ] Add imports (after the existing ones, around line 14):
      ```python
      from authglow.services.claim_policy import ClaimPolicyService
      from authglow.services.oauth_client import (
          OAuth2ClientStorage,
          ensure_system_oauth_client,
      )
      from authglow.services.rbac import RBACService
      ```
- [ ] Inside `create_admin_user` (after
      `await storage.create_user(admin_user)` at line 124), insert:
      ```python
      rbac = RBACService()
      admin_role_id = await rbac.ensure_admin_role()
      await rbac.assign_role_to_user_idempotent(
          user_id=admin_user.id,
          role_id=admin_role_id,
          actor_id=admin_user.id,
      )

      client_storage = OAuth2ClientStorage()
      await ensure_system_oauth_client(client_storage, settings)

      claim_policy = ClaimPolicyService()
      await claim_policy.ensure_system_client_policy(settings.oauth2_client_id)
      ```
- [ ] Change the bootstrap user's `scopes` from
      `["read", "write", "admin"]` to `["read", "write"]` (line 117).
      The `admin` authority is now RBAC-driven.

### [ ] 4.2 `../../backend/authglow/services/demo.py`

- [ ] Add imports:
      ```python
      from authglow.services.claim_policy import ClaimPolicyService
      from authglow.services.oauth_client import (
          OAuth2ClientStorage,
          ensure_system_oauth_client,
      )
      from authglow.services.rbac import RBACService
      ```
- [ ] In `seed_demo_user` (after the user creation / refresh
      block, around line 90), insert the same three-helper
      invocation as in `setup.py`.
- [ ] Change the demo user's `scopes` from
      `["read", "write", "admin"]` to `["read", "write"]` (line 97).
      The `admin` RBAC role replaces the OAuth `admin` scope.
- [ ] Refactor the early-return path
      (`if existing is not None: return password`) so the bootstrap
      helpers run regardless of whether the user pre-existed
      (the helpers are idempotent).

### [ ] 4.3 Tests

- [ ] `backend/tests/integration/test_setup.py` (or equivalent): new
      tests
- [ ] `test_setup_creates_admin_role_and_assignment` — wipe DB, run
      `create_admin_user`, assert the `admin` RBAC role exists and
      the bootstrap user is assigned to it.
- [ ] `test_setup_creates_system_oauth_client` — assert a DB record
      exists for `settings.oauth2_client_id` with `is_system=True`.
- [ ] `test_setup_creates_system_client_claim_policy` — assert
      `ensure_system_client_policy` wrote the two RBAC rules.
- [ ] `test_setup_idempotent` — call `create_admin_user` twice
      (second call returns 404), assert exactly one admin role,
      exactly one user, exactly one system client, exactly one
      policy.

### [ ] 4.4 Verification

- [ ] `rtk pytest tests/integration/test_setup.py -q`

**Commit**: `feat(setup): wire admin role + system client + claim
policy into bootstrap`

---

## [ ] Phase 5 — Remove the `scope=admin` bypass in `core/permissions.py`

**Goal**: `require_admin` is now purely RBAC-driven. The OAuth
`admin` scope no longer grants any privilege.

### [ ] 5.1 `../../backend/authglow/core/permissions.py`

- [ ] Remove lines 82-85 (the `if "admin" in scopes: return user_id`
      early bypass inside `PermissionChecker.__call__`).
- [ ] Replace the file-level `require_admin` definition (currently
      `def require_admin(): return require_role("admin")` at the
      bottom) with a comment pointing to `api/admin.py` (Phase 6
      puts the User-aware version there).
- [ ] Update the `PermissionChecker` docstring to reflect that the
      scope-bypass has been removed.

The `PermissionChecker` class itself stays: it still validates RBAC
permissions and roles. The `require_role` / `require_permission`
helpers stay: they continue to be used by `api/rbac.py` and any
future per-permission endpoints.

### [ ] 5.2 Tests

- [ ] `../../backend/tests/unit/test_permissions.py` (or equivalent):
      existing tests should still pass for the RBAC paths. New
      tests:
- [ ] `test_admin_scope_does_not_bypass_rbac` — build a token with
      `scopes=["admin"]` but no RBAC role → `PermissionChecker`
      rejects with 403.
- [ ] `test_scope_only_no_admin_role_rejected` — user has
      scopes=admin but no role assignment → rejected.

### [ ] 5.3 Verification

- [ ] `rtk pytest tests/unit/test_permissions.py -q`
- [ ] `rtk pytest tests/integration/test_rbac_jwt_injection.py -q`

**Commit**: `feat(security): remove scope=admin bypass in
PermissionChecker; admin is RBAC-only`

---

## [ ] Phase 6 — Centralise `require_admin` in `api/admin.py`, remove local duplicates

**Goal**: a single source of truth for the admin dependency. All
~30 endpoints use it.

### [ ] 6.1 `../../backend/authglow/api/admin.py`

- [ ] Add to the imports:
      ```python
      from authglow.services.rbac import RBACService
      ```
- [ ] Replace the local `require_admin` (around line 81) with a
      User-returning RBAC-based version:
      ```python
      async def require_admin(current_user: User = Depends(get_current_user)) -> User:
          """Require the caller to hold the ``admin`` RBAC role.

          Admin gating is RBAC-driven only. The OAuth ``admin`` scope is
          ignored — ``scope=admin`` does NOT grant admin access. A caller
          must have been assigned the ``admin`` role via the RBAC admin
          UI (or be the bootstrap admin user provisioned at setup) to
          satisfy this dependency.
          """
          rbac_service = RBACService()
          if not await rbac_service.user_has_role(current_user.id, "admin"):
              raise HTTPException(
                  status_code=status.HTTP_403_FORBIDDEN,
                  detail="Admin access required",
              )
          return current_user
      ```
- [ ] Add a companion helper for compound ownership+admin checks
      (used by `api/api_key.py`, `api/password_reset.py`, etc.):
      ```python
      async def user_has_admin_role(user_id: str) -> bool:
          """Return ``True`` if *user_id* currently holds the ``admin`` RBAC role.

          Helper for compound ownership/admin checks that do not fit
          the :func:`require_admin` dependency pattern.
          """
          return await RBACService().user_has_role(user_id, "admin")
      ```
- [ ] Make sure `status` is imported from `fastapi` (used in the
      new raise).

### [ ] 6.2 Remove local `require_admin` from sibling modules

For each of the following files:

- `../../backend/authglow/api/claim_policy.py` (line 67)
- `../../backend/authglow/api/oauth_client.py` (line 57)

Do:
- [ ] Delete the local `async def require_admin(...) -> User:` block.
- [ ] Add the import
      `from authglow.api.admin import require_admin` to the file's
      import block.
- [ ] Remove the now-unused `get_current_user` import if no other
      code path in the file still uses it.

The remaining `Depends(require_admin)` calls in those files keep
working because they reference the imported name from `api.admin`.

### [ ] 6.3 Tests

- [ ] `backend/tests/integration/test_admin.py` (or equivalent): new
      tests
- [ ] `test_admin_endpoint_with_admin_rbac_role_passes`
- [ ] `test_admin_endpoint_with_only_admin_scope_rejected` — bearer
      token has `scope=admin` in the JWT but the underlying user
      has no `admin` RBAC role → 403.
- [ ] `test_admin_endpoint_with_bootstrap_user_passes` — the user
      created by `create_admin_user` (now holding the `admin` role)
      can hit `/api/admin/*`.

### [ ] 6.4 Verification

- [ ] `rtk pytest tests/integration/test_admin.py -q`
- [ ] `rtk pytest tests/integration/test_api_key_claim_policy.py -q`

**Commit**: `feat(api): centralise require_admin in api.admin using
RBAC; remove local scope-based duplicates`

---

## [ ] Phase 7 — Replace inline `if "admin" in current_user.scopes` with RBAC checks

**Goal**: every endpoint that gated on `scope=admin` now gates on
the `admin` RBAC role.

### [ ] 7.1 Backend files to update

`grep -rn '"admin" not in current_user.scopes' backend/authglow/`
returns 0 hits after Phase 6. But there are still
`if "admin" not in current_user.scopes` (and the `in` variant)
inside compound ownership+admin checks. The files to sweep:

- `../../backend/authglow/api/api_key.py` — 11 hits at the time of the
  rollback. Each becomes
  `not await user_has_admin_role(current_user.id)`. Already
  partially converted in the half-implementation.
- `../../backend/authglow/api/password_reset.py` — 6 hits. Same
  conversion. Already partially converted in the half-implementation.
- `../../backend/authglow/api/auth.py` — 1 hit at the `invite_user`
  endpoint (line 1945). Replace with `Depends(require_admin)` from
  `api.admin`. Drop the now-unused `current_user: User` parameter
  on the route signature. Already converted in the half-implementation.

The bulk-conversion command (works on `api_key.py` and
`password_reset.py`; `auth.py` needs manual editing because the
parameter is also dropped):

```bash
# Inside each file, after adding the import:
# from authglow.api.admin import user_has_admin_role
sed -i '' 's/"admin" not in current_user.scopes/(not await user_has_admin_role(current_user.id))/g' \
  backend/authglow/api/api_key.py \
  backend/authglow/api/password_reset.py
```

Verify with
`grep -rn '"admin" (in|not in) current_user.scopes' backend/` — must
be empty.

- [ ] Run the sed conversion on `api_key.py`
- [ ] Run the sed conversion on `password_reset.py`
- [ ] Manually edit `api_key.py` and `password_reset.py` to add the
      `from authglow.api.admin import user_has_admin_role` import
- [ ] Manually edit `auth.py` invite_user endpoint
- [ ] Confirm `grep -rn '"admin" (in|not in) current_user.scopes' backend/`
      returns empty

### [ ] 7.2 Test fixture sweep (HIGHEST-RISK step)

The conversion changes the behaviour for users that held only the
OAuth `admin` scope (they get 403 now). The integration tests that
previously authenticated with `scope=admin` need to be updated.

Pattern that needs to change across integration tests:

```python
# OLD
test_user = User(..., scopes=["admin"])

# NEW (option A — user model change)
test_user = User(..., scopes=["read", "write"])  # no longer carries admin
# then in the test setup, before issuing admin requests:
rbac = RBACService()
role_id = await rbac.ensure_admin_role()
await rbac.assign_role_to_user_idempotent(test_user.id, role_id, actor_id=...)

# NEW (option B — direct helper)
admin = await make_admin_test_user(test_settings)  # factory that does both
```

The factory approach is cleaner for the dozens of tests that need
it. Add to `../../backend/tests/conftest.py`:

```python
@pytest_asyncio.fixture
async def admin_test_user(test_settings, storage) -> User:
    """Yield a User that has the ``admin`` RBAC role assigned.

    Use this fixture for any test that exercises an admin-gated
    endpoint — the OAuth ``admin`` scope is no longer a sufficient
    gate.
    """
    from authglow.services.rbac import RBACService

    user = User(
        id="admin-user-001",
        email="admin@example.com",
        hashed_password=hash_password("AdminP@ss123!"),
        is_active=True,
        scopes=["read", "write"],  # no longer carries the admin scope
        email_verified=True,
    )
    await storage.create_user(user)
    rbac = RBACService()
    role_id = await rbac.ensure_admin_role()
    await rbac.assign_role_to_user_idempotent(
        user_id=user.id, role_id=role_id, actor_id=user.id
    )
    return user
```

Then sweep:

```bash
grep -rln 'scopes=\["admin"\]' backend/tests/ | xargs sed -i '' 's/scopes=\["admin"\]/scopes=["read", "write"]/g'
```

…followed by a manual pass to add the `admin_test_user` fixture
where the test was previously using the literal
`scopes=["admin"]` pattern. This is the highest-risk change in the
whole refactor; do it file-by-file and re-run the suite at the end
of each.

- [ ] Add the `admin_test_user` factory fixture in
      `../../backend/tests/conftest.py`
- [ ] Run the `sed` sweep
- [ ] Manually file-by-file: add the `admin_test_user` fixture to
      every test that used `scopes=["admin"]` AND calls an admin
      endpoint. After each file, run:
      `rtk pytest tests/integration/test_<that_file>.py -q` and
      keep going only if it passes.
- [ ] Final check:
      `grep -rn 'scopes=\["admin"\]' backend/tests/` must be empty

### [ ] 7.3 Verification

- [ ] `grep -rn '"admin" (in|not in) current_user.scopes' backend/` is
      empty
- [ ] `grep -rn 'scopes=\["admin"\]' backend/tests/` is empty
- [ ] `rtk pytest tests/integration -q --tb=line 2>&1 | tail -10`

**Commit**: `feat(security): replace all scope=admin gates with RBAC
role checks`

---

## [ ] Phase 8 — API key: drop the `is_admin` scope check + remove the warning

**Goal**: `admin` is a normal scope value for API keys. The
`is_admin` parameter to `create_key` / `update_key` is now driven by
RBAC, not by the OAuth scope.

### [ ] 8.1 `../../backend/authglow/services/api_key.py`

- [ ] Remove the two `logger.warning("api_key_scope_filtered", ...)`
      blocks (one in `create_key` around line 175, one in
      `update_key` around line 471). The BOPLA subset filter
      (`_enforce_scope_subset`) stays — the warning was the only
      thing removed.
- [ ] Update the `is_admin` parameter docstring on `create_key` /
      `update_key` to clarify it's the RBAC-driven check, not a
      scope check.

### [ ] 8.2 `../../backend/authglow/models/api_key.py`

- [ ] Update the docstring on the `filtered_scopes` field (around
      line 117) to note that the `admin` scope is no longer a
      privileged value, and that the warning log was removed
      (the BOPLA filter still runs at the service layer; the
      surface is preserved on the response envelope).

### [ ] 8.3 `../../backend/authglow/api/api_key.py`

- [ ] Replace the two `is_admin="admin" in current_user.scopes`
      calls (in `create_api_key` and `update_api_key`) with
      `is_admin=await user_has_admin_role(current_user.id)`. The
      import was added in Phase 7.

### [ ] 8.4 Tests

- [ ] `../../backend/tests/unit/test_api_key.py` (or equivalent):
- [ ] `test_create_key_with_admin_scope_does_not_warn` — verifies
      the warning log is not emitted when an admin user requests
      `scopes=["admin", "read"]`.
- [ ] `test_create_key_with_admin_scope_filters_for_non_admin` — a
      non-admin user with `scopes=["read"]` requesting
      `scopes=["admin", "read"]` ends up with `granted=["read"]`
      silently (no warning). The response envelope still carries
      `filtered_scopes=["admin"]` for transparency.
- [ ] `test_create_key_with_admin_scope_keeps_all_for_admin` — an
      admin (RBAC) user requesting `scopes=["admin", "read"]` ends
      up with the full set granted (no filter).
- [ ] `backend/tests/integration/test_api_key.py`:
- [ ] `test_create_key_with_admin_scope_works_for_admin` —
      round-trip via the HTTP endpoint with a user that has the
      `admin` RBAC role and `scopes=["admin"]` in the request.
      Verify the key is created with `scopes=["admin"]`.

### [ ] 8.5 Verification

- [ ] `rtk pytest tests/unit/test_api_key.py -q`
- [ ] `rtk pytest tests/integration/test_api_key.py -q`

**Commit**: `feat(api-keys): drop is_admin scope check; remove the
api_key_scope_filtered warning log`

---

## [ ] Phase 9 — First-party tokens: route through the system client's claim policy

**Goal**: the cookie-based refresh flow stops emitting the implicit
`.../roles` / `.../permissions` empty-array defaults; instead the
system client's claim policy is consulted and emits the
RBAC-backed values.

### [ ] 9.1 `../../backend/authglow/api/auth.py`

Inside `cookie_refresh` (around line 1855-1866), change
`client_id=None` to `client_id=settings.oauth2_client_id`. Update
the surrounding comment from "default first-party rule set is
applied" to "the system client's claim policy is consulted; a
no-policy fallback is impossible because the bootstrap seeds a
policy on every first boot".

The other `client_id=None` callsites in `auth.py` are:

- Line 1455 (client_credentials grant, `user=None`): leave alone.
  M2M tokens are correctly first-party-only; the system client's
  policy emits nothing for a `user=None` subject anyway (RBAC
  sources produce empty), and STATIC rules aren't configured.
- Line 1861 (cookie refresh): change to
  `client_id=settings.oauth2_client_id`.

- [ ] Change line 1861 `client_id=None` →
      `client_id=settings.oauth2_client_id`
- [ ] Update the comment in `cookie_refresh` accordingly

### [ ] 9.2 Tests

- [ ] `backend/tests/integration/test_oauth_jwt.py` (or equivalent):
- [ ] `test_cookie_refresh_uses_system_client_policy` — issue a
      refresh, decode the new access token, assert the
      `https://authglow.example.com/claims/roles` claim is present
      (because the bootstrap seeded the policy and the test user
      has the `admin` RBAC role) and contains `["admin"]`.

### [ ] 9.3 Verification

- [ ] `rtk pytest tests/integration/test_oauth_jwt.py -q`
- [ ] `rtk pytest tests/integration/test_rbac_jwt_injection.py -q`

**Commit**: `feat(tokens): first-party cookie refresh routes through
the system client's claim policy`

---

## [ ] Phase 10 — Frontend: system client badge + delete disabled

**Goal**: the system client appears in the admin OAuth clients
list with a "System" badge. The delete affordance is disabled
with a tooltip explaining why.

### [ ] 10.1 `../../frontend/src/pages/admin/AdminOAuthClientsPage.tsx`

- [ ] Add `is_system?: boolean` to the `OAuthClient` interface
      (line 27).
- [ ] In the row-actions column, render the delete button with
      `disabled={c.is_system}` and a
      `title="System OAuth clients cannot be deleted."` attribute.
      The button is still visible (so the user sees the affordance)
      but greyed out. Use the existing `Trash2` icon (already
      imported).
- [ ] Add a "System" badge to the client name when `c.is_system`
      is true. Reuse the existing `api-key-claim-policy-default-badge`
      style as a reference, or create a dedicated
      `data-testid="oauth-client-system-badge"`.
- [ ] Ensure the `Claims` tab still opens for the system client
      (no extra guard — the existing `setClaimsClient` flow works
      for any client id, the only difference is that the saved
      policy is the one seeded at bootstrap).

### [ ] 10.2 Tests

- [ ] `../../frontend/src/pages/admin/AdminOAuthClientsPage.test.tsx`:
- [ ] `test_system_client_renders_system_badge` — mock an
      `OAuthClient` with `is_system: true` in the API response,
      expect the badge to be in the document.
- [ ] `test_system_client_delete_button_is_disabled` — same setup,
      expect the delete button to have the `disabled` attribute.
- [ ] `test_non_system_client_delete_button_enabled` — regression
      check: a regular client still has the button enabled.

### [ ] 10.3 Verification

- [ ] `cd frontend`
- [ ] `npm test -- src/pages/admin/AdminOAuthClientsPage.test.tsx`
- [ ] `npm run lint`
- [ ] `npm run build`

**Commit**: `feat(admin): system OAuth clients show a "System"
badge and have delete disabled`

---

## [ ] Phase 11 — Frontend: clear "admin" scope from UI (no longer relevant)

**Goal**: stop showing the `admin` scope as a special value in any
UI surface. The scope is still a valid string, but it no longer
implies any privilege.

### [ ] 11.1 Audit

`grep -rn '"admin"' frontend/src/ --include='*.tsx' --include='*.ts'`
returns 0 hits. The frontend never rendered the `admin` scope as
a badge or label — it only displayed the scope list as plain text
in the JWT preview.

If anything does show up (e.g. a "highlighted scope" effect tied
to `scope === 'admin'`), remove that effect: the scope is a plain
string.

- [ ] Run the grep
- [ ] If hits are present, remove the special-case UI

### [ ] 11.2 Verification

- [ ] `cd frontend`
- [ ] `grep -rn "'admin'\|'admin'" src/` — quick visual scan
- [ ] No code changes expected. If changes were made:
      `npm run lint && npm run build`

---

## [ ] Phase 12 — End-to-end verification (db wipe + reboot)

**Goal**: prove that a fresh boot self-bootstraps the platform. The
operator runs this once before merging.

### [ ] 12.1 Procedure

- [ ] `cd backend`
- [ ] `rm -rf data/users/ data/keys/` — wipe all persisted state
- [ ] `uvicorn main:app --reload` — boot
- [ ] Browser: hit `/setup`, create the admin user
- [ ] Verify the new account form accepts the password
- [ ] Verify a redirect to the login page happens
- [ ] Login with the admin credentials
- [ ] Decode the `access_token` (jwt.io or your decoder of choice)
- [ ] Assert the following claims are present and non-empty:
      - `iss = http://localhost:8001`
      - `aud / azp = settings.oauth2_client_id` ("change-me-in-production"
        or the dev default)
      - `scope = "openid profile email read write offline_access"`
        (NO "admin" in the scope)
      - `sub = <user id>`
      - `https://authglow.example.com/claims/roles = ["admin"]`
      - `https://authglow.example.com/claims/permissions = [...]`
        (the 12 default permissions)
- [ ] Open the admin UI
- [ ] Verify Admin → OAuth Clients → "AuthGlow System Client" is
      in the list
- [ ] Verify it has a "System" badge
- [ ] Verify the delete button is disabled
- [ ] Verify the Claims tab opens and shows two rules
      (`rbac_roles`, `rbac_permissions`), both into `access_token`
      and `id_token`
- [ ] Create a new API key with `scopes=["read", "write", "admin"]`
      (the user is RBAC admin)
- [ ] Verify the key is created with all three scopes (no filter
      because RBAC admin)
- [ ] Verify the response envelope does NOT include a
      `filtered_scopes` entry (or it is empty)
- [ ] Use the new key to call `GET /api/admin/stats` → 200 (the
      RBAC admin role is checked at the dependency level, the
      `admin` OAuth scope in the key is ignored)
- [ ] Use a SECOND key, this one created by a non-admin user with
      only `scopes=["read"]` requesting `scopes=["admin", "read"]`
- [ ] Verify the key ends up with `scopes=["read"]` only
- [ ] Call `GET /api/admin/stats` with that key → 403
- [ ] Try to delete the system client from the admin UI → the
      button is disabled; nothing happens on click
- [ ] Try to delete the system client via curl:
      `curl -X DELETE /api/oauth-clients/<system-id>` → 403 with
      body "System OAuth2 clients cannot be deleted."

If any step fails, do not merge. Open a follow-up issue describing
the deviation and link to the phase that owns the affected code.

---

## [ ] Phase 13 — Final cleanup: docs, CHANGELOG, deprecation notice

**Goal**: surface the breaking change to operators.

### [ ] 13.1 Files

- [ ] `backend/CHANGELOG.md` (create if absent) — add an entry under
      the current version:
      ```
      ## [Unreleased]

      ### Breaking changes
      - **Admin gating is now RBAC-driven only.** The OAuth ``admin``
        scope no longer grants any privilege. The bootstrap admin
        user is granted the ``admin`` RBAC role at setup; new admins
        must be promoted via the RBAC admin UI. Existing deployments
        must wipe the database and re-run setup — there is no
        migration script. The ``admin`` OAuth scope can still be
        carried on a user or an API key, but it is treated as a
        plain string.
      - **System OAuth client is created at bootstrap.** A new
        ``is_system=true`` OAuth client named "AuthGlow System
        Client" appears in the admin list. Its redirect URI defaults
        to ``settings.oauth2_first_party_redirect_uri``. The admin
        UI surfaces a "System" badge and disables the delete button.
        A claim policy is seeded with two RBAC-backed rules
        (``.../roles`` and ``.../permissions``) so first-party access
        tokens carry real RBAC data.
      - **First-party access tokens route through the system
        client's claim policy.** Cookie-based refresh now consults
        ``settings.oauth2_client_id`` instead of the implicit
        first-party default rules. The user-visible effect: tokens
        now carry ``.../roles`` and ``.../permissions`` populated
        from RBAC (when the user has any assignments) and the
        empty-array defaults are gone.
      ```
- [ ] `../../README.md` — add a "Bootstrap" section that documents the
      four artefacts the setup endpoint creates (admin user, admin
      role, system client, claim policy) and the operator's
      responsibility to rotate the system client secret in
      production.
- [ ] `../FEATURES.md` — link the new "RBAC admin gate" and
      "System OAuth client" sections from the table of contents.

### [ ] 13.2 Verification

- [ ] `cd backend`
- [ ] `ls CHANGELOG.md`
- [ ] `grep -n "admin" CHANGELOG.md` — the new section is present

**Commit**: `docs: document RBAC-only admin gate and system OAuth
client`

---

## End-to-end test pass (post every phase)

After every phase, run the full backend suite:

- [ ] `cd backend`
- [ ] `rtk ruff check authglow/ tests/` is clean
- [ ] `rtk mypy authglow/` is clean
- [ ] `rtk pytest -q --tb=line -n auto` all pass

A phase is "done" only when:
- `ruff` is clean (no new warnings)
- `mypy` is clean (no new errors)
- All tests pass

For the frontend, after every phase that touches `.tsx`/`.ts`:

- [ ] `cd frontend`
- [ ] `npm test -- <affected files>`
- [ ] `npm run lint`
- [ ] `npm run build`

---

## Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Existing test files rely on `scopes=["admin"]` for admin auth | **High** | Phase 7.2 ships an `admin_test_user` factory fixture and a sweep that rewrites the pattern. Sweep file-by-file, re-run the suite at each step. |
| `admin` scope on existing user `User.scopes` (e.g. imported from a backup) silently loses privileges after the wipe | Low | Greenfield assumption is explicit. The CHANGELOG entry in Phase 13 calls this out. |
| `ensure_system_oauth_client` is called twice in the same setup boot (e.g. via a test that re-runs setup) and the second call fails because the row exists | **None** (idempotent: early return on `get_client` hit) | None needed. |
| The system client's `client_secret` is stored as a bcrypt hash. If the operator rotates `settings.oauth2_client_secret` after setup, the frontend's login breaks. | Medium | Documented in the Phase 13 README section: the system client is bound to the env-var secret. Rotating the env without re-bootstrapping leaves the operator with a non-functional login. Add a TODO for a "rotate system client secret" admin endpoint (out of scope for this refactor). |
| Token issuance is slowed by the extra RBAC lookup at the `require_admin` dependency | Low | Admin endpoints are not high-traffic. If it becomes a problem later, add a `roles` claim to the access token and check it in-process. |
| The system client is listed in the admin UI but operators don't realise they should NOT rotate its `client_secret` from the admin UI (it would diverge from the env) | Medium | Add a "managed by environment" hint near the system client's settings in `AdminOAuthClientsPage`. Mention it in the Phase 13 README. |
| A new admin user (promoted via RBAC UI) is not the bootstrap user, so they don't carry `is_bootstrap=True`. Their account can be deactivated by a future admin. | Low | Out of scope. Documented as expected behaviour. |

---

## Test fixture catalogue (after Phase 7)

These fixtures should exist in `../../backend/tests/conftest.py` (or a
dedicated `tests/fixtures.py`):

| Fixture | Purpose |
|---|---|
| `admin_test_user` | A user with the `admin` RBAC role and `scopes=["read", "write"]`. Use this for any test that exercises an admin endpoint. |
| `non_admin_test_user` | A plain user with `scopes=["read", "write"]`, no RBAC roles. |
| `bootstrap_admin_test_user` | A user with `is_bootstrap=True` and the `admin` RBAC role, simulating what `create_admin_user` produces. |
| `rbac_admin_token` | Mints a JWT for `admin_test_user` with the right `roles` claim. |
| `rbac_non_admin_token` | Mints a JWT for `non_admin_test_user`. |
| `system_oauth_client` | The DB record produced by `ensure_system_oauth_client`, with the matching claim policy. |

If a test needs an old `scope=admin` bearer, mint a custom JWT in
the test body with the desired scope and the matching RBAC role —
no shared fixture for this case.

---

## Glossary of changed names

- `require_admin` (function, `core/permissions.py`) → **removed** in
  favour of `require_admin` in `api/admin.py`. The semantics
  changed: the new one is async and queries RBAC, not the OAuth
  scope.
- `require_admin` (function, `api/admin.py`) → **behaviour change**:
  now RBAC-driven. Existing callers get the new semantics for free
  via re-export.
- `is_admin` parameter on `create_key` / `update_key`
  (`services/api_key.py`) → **semantics change**: now means "RBAC
  admin role", not "OAuth `admin` scope in caller scopes". The
  BOPLA bypass it gates still works.
- `filtered_scopes` field on `APIKeyCreateResponse`
  (`models/api_key.py`) → **still computed** at the service layer
  (no longer logged). The `admin` scope is just a normal scope
  that gets filtered out for non-admin callers like any other.

---

## Final commit sequence

```
feat(rbac): add is_system field to OAuth2Client and block DELETE for system clients
feat(rbac): add ensure_admin_role and assign_role_to_user_idempotent helpers
feat(bootstrap): add ensure_system_oauth_client and ensure_system_client_policy helpers
feat(setup): wire admin role + system client + claim policy into bootstrap
feat(security): remove scope=admin bypass in PermissionChecker; admin is RBAC-only
feat(api): centralise require_admin in api.admin using RBAC; remove local scope-based duplicates
feat(security): replace all scope=admin gates with RBAC role checks
feat(api-keys): drop is_admin scope check; remove the api_key_scope_filtered warning log
feat(tokens): first-party cookie refresh routes through the system client's claim policy
feat(admin): system OAuth clients show a "System" badge and have delete disabled
docs: document RBAC-only admin gate and system OAuth client
```

Each commit passes the full backend + frontend test suite.
