# AGENTS.md

Guidelines for AI coding agents working in the AuthGlow repository.

## Project Overview

AuthGlow is an authentication platform with a Python/FastAPI backend (`backend/`) and a React/TypeScript frontend (`frontend/`).

## Build & Dev Commands

### Backend (from `backend/`)

```bash
# Run the dev server
uvicorn main:app --reload

# Run all tests (parallel via pytest-xdist)
pytest -q --tb=line -n auto

# Run a single test file
pytest tests/unit/test_jwt.py

# Run a single test by name
pytest tests/unit/test_jwt.py::TestJWTTokenCreation::test_create_access_token_roundtrip -v

# Lint (ruff)
ruff check authglow/

# Format (ruff)
ruff format authglow/

# Type check (mypy)
mypy authglow/
```

### Frontend (from `frontend/`)

```bash
# Install dependencies
npm install

# Dev server
npm run dev

# Build (type-check + bundle)
npm run build

# Lint
npm run lint

# Unit tests (vitest)
npm test                    # run all
npm test -- path/to/file    # run single file

# E2E tests (playwright)
npx playwright test
npx playwright test e2e/flows/login-dashboard.spec.ts   # single spec
```

## Test anti-regressione

Tests serve as regression protection. After every change:

- **Backend** → run only the test files matching the changed area
  (e.g. modified `services/jwt.py` → `tests/unit/test_jwt.py`).
  Full suite (`-n auto`) only for `core/` changes or before committing.
- **Frontend** → run only the test file(s) for the changed component
  (`npm test -- path/to/file`).
- **E2E** → only for cross-cutting flows touched by the change
  (login, registration, OAuth2, MFA). Uses Playwright.

When the full backend suite is needed, use `pytest -q --tb=line -n auto`
(requires `pytest-xdist`). Pass `timeout: 300000` to the Bash tool —
the timeout parameter belongs to the Bash tool, not pytest.

## Code Style — Backend (Python 3.11)

### Formatting

- **Formatter/Linter**: ruff (line length 100, double quotes, 4-space indent).
- Import sorting enforced via ruff isort (`select = ["I"]`).
- E501 (line length) is ignored in linting — handled by the formatter.

### Import Ordering

Three groups separated by blank lines, each alphabetically sorted:
1. Standard library (`import os`, `from datetime import datetime`)
2. Third-party (`import bcrypt`, `from fastapi import ...`)
3. First-party (`from authglow.core.config import ...`)

Private modules use leading underscore: `from authglow.core.config import _new_kid`.
Lazy imports inside functions for circular-dependency avoidance.

### Type Annotations

- Use `typing` module generics: `List[str]`, `Optional[str]`, `Dict[str, Any]`.
- Built-in generics (`list[str]`, `dict[str, object]`) are acceptable in newer code.
- Use `Optional[X]` not `X | None` (3.11 compat).
- Return type annotations required on all functions.
- `TypedDict` for typed dicts, `NoReturn` for functions that always raise.
- Pydantic models: full annotations on all fields, `Field(default_factory=...)` for mutable defaults.

### Naming

| Element              | Convention            | Example                       |
|----------------------|-----------------------|-------------------------------|
| Functions/methods    | `snake_case`          | `get_current_user`            |
| Private functions    | `_leading_underscore` | `_derive_key`                 |
| Classes              | `PascalCase`          | `JWTService`, `UserStorage`   |
| Pydantic models      | `PascalCase` + suffix | `UserCreate`, `TokenData`     |
| Constants            | `UPPER_SNAKE_CASE`    | `PREFIX_LENGTH`               |
| Private constants    | `_UPPER_SNAKE_CASE`   | `_KEY_PREFIX`                 |
| Dependency injectors | `get_<name>`          | `get_user_storage`            |
| Test classes         | `Test<Subject>`       | `TestJWTTokenCreation`        |
| Test methods         | `test_<scenario>`     | `test_expired_token_rejected` |

### Error Handling

- Use `fastapi.HTTPException` with explicit `status_code` and `detail` message.
- Custom exceptions for domain logic (e.g. `APIKeyLockedException`, `ConcurrentWriteError`).
- Catch custom exceptions in route handlers and translate to `HTTPException`.
- Use `status.HTTP_XXX_*` constants for standard codes.
- Security-critical paths: use `NoReturn` + `handle_failed_login()` pattern to prevent user enumeration.

### Logging

- **structlog** exclusively (no stdlib `logging`).
- Single logger: `structlog.get_logger("authglow.audit")`.
- Structured JSON output to stdout.
- Mask/hash PII before logging based on `audit_email_log_level` setting.

### Pydantic Models

- All models inherit from `pydantic.BaseModel`.
- Request/response models separate from domain models (`UserCreate` vs `User`).
- Use `model_dump()` (not `.dict()`), `model_copy(update=...)` (not `.copy()`).
- `field_validator` for custom field validation, `Field(...)` for constraints.
- Settings via `pydantic_settings.BaseSettings` with `SettingsConfigDict`.

### FastAPI Patterns

- Each module defines `router = APIRouter()` included in `main.py`.
- Dependency injection via `Depends(get_<service_factory>)`.
- Rate limiting: `@limiter.limit("5/minute")` with `request: Request` as first param.
- Response models declared on decorators: `response_model=UserResponse`.
- All handlers are `async def`. All service calls use `await`.
- File I/O wrapped with `asyncio.to_thread()` (see `async_io.py`).

### Testing (pytest)

- `pytest-asyncio` with `asyncio_mode = "auto"` — no per-test `@pytest.mark.asyncio` needed.
- Fixtures import inside body to avoid circular deps, use `patch("authglow.*.get_settings")`.
- `autouse` fixture for settings override across all tests.
- Assertions: plain `assert` (no `self.assertEqual`).
- `pytest.raises` for exception testing.
- Test files: `tests/unit/`, `tests/integration/`, `tests/conftest.py`.

**Running tests — token-saving rules:**

- When running the full suite, always use `pytest -q --tb=line -n auto` to minimize output.
- Run only the test files matching the changed area, not the full suite every time
  (e.g. modified `services/jwt.py` → `tests/unit/test_jwt.py`).
- Pass `timeout: 300000` to the Bash tool for the full suite — the timeout
  parameter belongs to the Bash tool, not pytest.
- Show only failures and warning summary — never dump full tracebacks unless debugging a specific failure.
- **Pre-existing test failures**: this repo has known failures (Python 3.13 event loop, CSP mismatch, `setup_page` import). After every test run, separate failures into two buckets: (a) files you modified — fix these immediately; (b) untouched files — report them clearly and **ask the user** whether to investigate. Never auto-fix pre-existing failures without asking.

### Other Conventions

- **UTC everywhere**: use `utcnow()` from `authglow.core.datetime`, never naive datetimes.
- **Secrets**: `secrets.token_urlsafe()` / `secrets.token_hex()` for crypto randomness.
- **Concurrency**: `named_lock()` from `authglow.core.concurrency` for atomic file ops.
- **Caching**: `functools.lru_cache` for pure functions, `cachetools.TTLCache` for TTL caches.
- **Module docstrings**: every module starts with a triple-quoted description.
- **Function docstrings**: Google/NumPy-like style on public functions.

## Code Style — Frontend (TypeScript/React)

### Tooling

- **TypeScript** with `strict`-ish flags: `noUnusedLocals`, `noUnusedParameters`, `verbatimModuleSyntax`.
- **ESLint** flat config with `typescript-eslint`, `react-hooks`, `react-refresh`.
- **Vite** for bundling. **Tailwind CSS** for styling. **shadcn/ui** for primitives.

### Import Ordering

1. React/library imports (`react`, `react-router-dom`, `@tanstack/react-query`)
2. Path-aliased imports (`@/lib/*`, `@/hooks/*`, `@/stores/*`, `@/components/*`)
3. Relative imports (`./Sibling`, `../helper`) — only for co-located files

- Use `import type` for type-only imports (enforced by `verbatimModuleSyntax`).
- `@/` alias maps to `./src/*`. Use it for all cross-directory imports.
- No barrel files / `index.ts` re-exports — import directly by file path.

### TypeScript Patterns

- `interface` for object shapes (props, API responses, store state).
- `type` for unions, string literal unions, derived types.
- Props interfaces suffixed with `Props`: `PageHeaderProps`.
- Generics extensively used in API layer: `api.get<AuthUser>(...)`.
- Minimize type assertions; prefer type narrowing.

### Naming

| Element                | Convention           | Example                   |
|------------------------|----------------------|---------------------------|
| Component files        | `PascalCase.tsx`     | `LoginForm.tsx`           |
| Non-component files    | `camelCase.ts`       | `authStore.ts`            |
| UI primitives (shadcn) | `kebab-case.tsx`     | `button.tsx`              |
| Test files             | `kebab-case.test.ts` | `phase2-auth.test.ts`     |
| E2E specs              | `kebab-case.spec.ts` | `login-dashboard.spec.ts` |
| Components             | `PascalCase`         | `StatusBadge`             |
| Functions/hooks        | `camelCase`          | `useAuth`, `formatDate`   |
| Event handlers         | `handle` prefix      | `handleDelete`            |
| Custom hooks           | `use` prefix         | `useAuth`, `useTheme`     |
| Constants              | `UPPER_SNAKE_CASE`   | `API_URL`, `ROUTES`       |
| Store hooks            | `use<Name>Store`     | `useAuthStore`            |

### Component Patterns

- **100% functional components**. Named exports only (no default exports except `App.tsx`).
- Props defined as named `interface` above component, destructured in params.
- Internal helper components: `function Name()` (not exported), defined in same file.
- `React.forwardRef` only for shadcn/ui primitives.
- Code splitting via `React.lazy()` with `.then((m) => ({ default: m.ComponentName }))`.

### State Management

- **Zustand** for client state. Separate `State` and `Actions` interfaces, intersected as `Store`.
- Convenience hooks (`useAuth`) wrapping store selectors for cleaner component APIs.
- **TanStack Query** for server state. Custom `useApiQuery` / `useApiMutation` wrappers.
- Query keys: `string[]` with dynamic segments. Conditional queries via `{ enabled }`.

### CSS/Styling

- **Tailwind utility classes** in JSX `className`. No CSS modules or styled-components.
- `cn()` utility (clsx + tailwind-merge) for conditional/merged classes.
- Design tokens via CSS variables: `text-text-primary`, `bg-surface-1`, `border-semantic-error`.
- shadcn/ui components use `class-variance-authority` (CVA) for variants.
- Common patterns: `rounded-xl`, `transition-colors`, `hover:scale-[1.02]`.

### Error Handling (Frontend)

- Custom `ApiError` class in `api.ts` with `status` and `data`.
- 401 responses auto-clear auth and redirect to `/auth/login`.
- Component errors: `try/catch` in event handlers, error state in `useState<string>`.
- Error UI: inline alerts with `bg-semantic-error/10 text-semantic-error`.
- Success feedback: `useState<boolean>` auto-cleared with `setTimeout`.

### Forms

- **react-hook-form** + **zod** validation.
- Schema defined at module level, type inferred via `z.infer<typeof schema>`.
- `useForm<T>({ resolver: zodResolver(schema) })`.
- Validation errors: `errors.fieldName && <p role="alert">{errors.fieldName.message}</p>`.

### Testing

- **Vitest** for unit/integration tests. `import { describe, it, expect } from 'vitest'`.
- **Playwright** for E2E. Serial execution (`workers: 1`). Projects: chromium + mobile.
- E2E helpers in `auth.setup.ts`: `injectAuth()`, `clearAuth()`, `loginViaUI()`.
- Use `data-testid` attributes for stable selectors in E2E tests.
- `role="alert"` on error messages for accessibility.

### Accessibility

- `aria-label` on icon-only buttons and navigation.
- `htmlFor` matching input `id` on labels.
- Semantic HTML: `<nav>`, `<section>`, `<main>`, `<aside>`.
- `role="alert"` on error messages.

## Architecture Notes

```
backend/
  authglow/
    api/          # FastAPI routers (HTTP layer)
    core/         # Config, crypto, cache, rate_limit, datetime, password
    middleware/   # Security headers, request size, HTTPS enforcement
    models/       # Pydantic data models
    services/     # Business logic (thin facade over repositories)
    repositories/ # ⭐ NEW: Repository pattern abstraction
      protocols.py        # 30 Protocol contracts (runtime_checkable)
      exceptions.py       # EntityNotFoundError, EntityAlreadyExistsError
      dependencies.py     # FastAPI factory functions (one per entity)
      file/              # File-based impls (current backend)
        base.py           # BaseFileRepository (fsspec + AsyncFileSystem)
        <entity>.py       # 1 per entity (token_blacklist, csrf, user, ...)
  tests/
    unit/
      repositories/
        test_protocols.py   # ⭐ 20+ parametrized conformance checks
        test_in_memory.py    # ⭐ 7 in-memory smoke tests
        file/                # Per-impl File tests
          test_<entity>.py   # 1 per entity (20+ entities)
      test_<service>.py
    integration/  # Cross-module tests
    conftest.py   # Shared fixtures (incl. _override_settings autouse)

frontend/src/
  lib/            # api.ts, utils.ts, constants.ts
  stores/         # Zustand stores (authStore, playgroundStore)
  hooks/          # Custom hooks (useApi, useAuth, useTheme)
  components/
    ui/           # shadcn/ui primitives
    layout/       # AppShell, Sidebar, TopBar
    shared/       # LoadingState, ErrorState, ConfirmDialog, etc.
  pages/          # Route components
  styles/         # globals.css with Tailwind + design tokens
```

### Repository Pattern (post-Fase 21)

The `authglow/repositories/` layer was introduced in **Fase 0**
and completed in **Fase 21** (see `docs/REFACTOR_REPOSITORY_PLAN.md`
for the full 21-phase migration history).

**Key principles**:

- **Services depend on Protocols, not impls.** Every service
  constructor takes optional `repository` arguments and falls
  back to a FastAPI factory via
  `repositories.dependencies.get_<entity>_repository()`.
- **Cross-entity atomicity lives in services**, not repos.
  The `UserService` facade holds the `named_lock` for
  `create_user` / `update_email` / `delete_user` (which
  span User + EmailIndex + FederatedIdentity).
- **Add a new backend (e.g. Postgres) in 3 steps**: (1)
  `pip install <dep>`, (2)
  `repositories/<backend>/<entity>.py` with
  `<Backend><Entity>Repository(<Protocol>)`, (3) update the
  factory in `repositories/dependencies.py`. **Zero
  changes** to `services/` or `api/`.
- **The conformance test
  `tests/unit/repositories/test_protocols.py`** parametrizes
  every Protocol × every impl, so adding a new backend
  means adding 1 line to `_IMPL_TABLE` — the conformance
  test then validates the new impl automatically.
- **The in-memory smoke test
  `tests/unit/repositories/test_in_memory.py`** proves the
  service↔repo protocol boundary works with any impl that
  satisfies the Protocol contracts (the `UserService`
  facade is exercised end-to-end with `InMemoryUserRepository`
  + `InMemoryEmailIndexRepository` +
  `InMemoryFederatedIdentityRepository`).

**Repository impl hierarchy**:

```
BaseFileRepository  (authglow/repositories/file/base.py)
  ├── shared fsspec + AsyncFileSystem handling
  ├── atomic write helpers (_write_json_atomic, _read_json, _glob, _delete)
  ├── path helpers (_path, _ensure_parent)
  └── lru_cache bypass via settings= kwarg on ctor

File<Entity>Repository(BaseFileRepository, <Entity>Repository)
  ├── Pydantic round-trip (model_dump / model_validate)
  ├── backend-specific concerns (PII encryption, HMAC keys, CAS)
  └── public surface = Protocol methods

FileKeyStoreRepository  (authglow/repositories/file/keystore.py)
  ├── BaseFileRepository subclass with root_dir=settings.keys_dir
  ├── _version field in keyring.json for cloud atomicity (_write_json_versioned)
  └── for_keys_dir() classmethod for lru_cache bypass at startup
```

**Service implementation hierarchy**:

```
Service.__init__(repository=None, ...)
  ├── if repository is None: factory = get_<entity>_repository(settings=self.settings)
  ├── else: use the injected repository directly
  └── the factory is the single point that picks the File impl today
       (tomorrow, a SQL impl could be selected by Settings.backend)

Service.create_user(user) [UserService cross-entity example]
  ├── async with self._lock(f"user:{user.id}"), self._lock("email_index")
  ├── await self._email_index_repo.lookup(...)  # duplicate check
  ├── await self._user_repo.create(user)        # single-entity mutation
  └── await self._email_index_repo.insert(...)  # secondary index
```

**Lru_cache bypass pattern** (CRITICAL for test isolation):

`BaseFileRepository.__init__` calls
`authglow.repositories.file.base.get_settings()` (NOT
`authglow.core.config.get_settings`). The autouse
`_override_settings` fixture patches
`authglow.core.config.get_settings` only, so the File
repos would hit the singleton `lru_cache` and always read
the FIRST test's `Settings` instance.

**Fix**: every factory in `repositories/dependencies.py`
accepts `settings: Settings | None = None`, and the
service passes `self.settings` (the patched, per-function
value) explicitly. Without this fix, `_storage_path` is
shared across tests → `TestAccountLockout` etc. fail with
"User with email <x> already exists" on the 2nd test
of the class.

For the keyring (Fase 20), the
`FileKeyStoreRepository.__init__` takes `settings=` for the
same reason. The `for_keys_dir()` classmethod additionally
takes a `keys_dir` + `secret_key` for the startup path in
`core/config.py: get_or_generate_keyring` (which runs BEFORE
the lru_cache is bypassed).

### Keeping ARCHITECTURE.md current

After structural changes (new router, service, repository, store, page),
update `ARCHITECTURE.md` to keep the directory maps and reference table accurate.

## Secret Management

AuthGlow is regularly scanned by GitGuardian. The repo's policy is: **no real secret ever touches git history**. This section covers how that's enforced, how to handle test fixtures, and what to do if a real secret is leaked.

### What's already in place

- `.env` is gitignored at the repo root (`.gitignore:138`).
- RSA signing keys are generated at runtime in `backend/tests/conftest.py:_generate_rsa_keys()` and stored in a session-scoped temp dir — never committed.
- `.env.example` is the canonical template for new environments and contains placeholder values only.
- A pre-commit `gitleaks` hook (`.pre-commit-config.yaml`) blocks commits that introduce real secrets.
- A `.gitguardian.yaml` path-allowlist at the repo root prevents test fixtures from generating false-positive alerts.

### How to generate secrets in dev

```bash
# Symmetric SECRET_KEY (sessions, encrypted blobs)
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"

# OAuth 2.0 client secret
python -c "import secrets; print('OAUTH2_CLIENT_SECRET=' + secrets.token_urlsafe(32))"

# Passkey / WebAuthn challenge entropy uses the same helper internally.
```

Copy the printed line into `backend/.env` (which is gitignored).

### Rotation policy

| Secret                                | When to rotate                                                                                                                    |
|---------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------|
| `SECRET_KEY`                          | On every major release, or **immediately** on any suspected leak. Invalidates all sessions and encrypted blobs.                   |
| `OAUTH2_CLIENT_SECRET`                | On request from a client, or on suspected leak. Requires re-consent flow.                                                         |
| JWT signing key                       | Automatic every 90 days via `jwt_auto_rotate=True` (see `authglow/core/config.py`). Manual rotation is exposed via the admin API. |
| SMTP / SendGrid / Mailgun credentials | Every 180 days, or on personnel change.                                                                                           |

### What to do if GitGuardian fires a real alert

1. **Revoke the secret immediately** at the issuing provider (rotate, delete, or block the key).
2. Strip the secret from history:
   ```bash
   pip install git-filter-repo
   git filter-repo --invert-paths --path <file-or-glob>
   git push --force-with-lease
   ```
3. Open a post-mortem issue tagged `security` even for false positives — update `.gitguardian.yaml` or `backend/tests/.gitleaks.toml` so the next scan learns from it.
4. If a private key was leaked, treat the corresponding public key as compromised: rotate the JWT keyring (`keyring.json`) and force a re-consent for OIDC clients.

### Test fixtures (where the noise comes from)

Most GitGuardian alerts on this repo are **false positives inside `backend/tests/`**: the suite contains strings that match generic-secret heuristics (32-char key material in `test_jwt_key_rotation.py`, the canonical RFC 6238 TOTP seed `JBSWY3DPEHPK3PXP` in `test_mfa.py`, bcrypt-style placeholders in `test_admin_users_phase2.py`, and plaintext test passwords in `test_registration.py`).

When adding new test code:

- **Reuse existing fixtures** from `backend/tests/conftest.py` (`test_user`, `test_admin_user`, `test_settings`, `mfa_service`, etc.) instead of inventing new plaintext passwords or secrets.
- For one-off values, generate at runtime:
  ```python
  import secrets
  fake_token = secrets.token_urlsafe(16)
  ```
- Never copy a real-looking secret into a test. If a test must exercise a *specific* format, derive it from `secrets` rather than hardcoding it.
- If a new fixture value keeps tripping gitleaks, add a targeted regex to the `[allowlist]` block in `backend/tests/.gitleaks.toml` **with a comment explaining why it's safe**.

### Pre-commit setup for new contributors

```bash
pip install pre-commit
pre-commit install
pre-commit run gitleaks --all-files   # one-time full scan
```

Once installed, every `git commit` automatically runs gitleaks on staged files. To skip (not recommended): `git commit --no-verify`.
