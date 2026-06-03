# AGENTS.md

Guidelines for AI coding agents working in the AuthGlow repository.

## Project Overview

AuthGlow is an authentication platform with a Python/FastAPI backend (`backend/`) and a React/TypeScript frontend (`frontend/`).

## Build & Dev Commands

### Backend (from `backend/`)

```bash
# Run the dev server
uvicorn main:app --reload

# Run all tests
pytest

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

| Element | Convention | Example |
|---|---|---|
| Functions/methods | `snake_case` | `get_current_user` |
| Private functions | `_leading_underscore` | `_derive_key` |
| Classes | `PascalCase` | `JWTService`, `UserStorage` |
| Pydantic models | `PascalCase` + suffix | `UserCreate`, `TokenData` |
| Constants | `UPPER_SNAKE_CASE` | `PREFIX_LENGTH` |
| Private constants | `_UPPER_SNAKE_CASE` | `_KEY_PREFIX` |
| Dependency injectors | `get_<name>` | `get_user_storage` |
| Test classes | `Test<Subject>` | `TestJWTTokenCreation` |
| Test methods | `test_<scenario>` | `test_expired_token_rejected` |

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

| Element | Convention | Example |
|---|---|---|
| Component files | `PascalCase.tsx` | `LoginForm.tsx` |
| Non-component files | `camelCase.ts` | `authStore.ts` |
| UI primitives (shadcn) | `kebab-case.tsx` | `button.tsx` |
| Test files | `kebab-case.test.ts` | `phase2-auth.test.ts` |
| E2E specs | `kebab-case.spec.ts` | `login-dashboard.spec.ts` |
| Components | `PascalCase` | `StatusBadge` |
| Functions/hooks | `camelCase` | `useAuth`, `formatDate` |
| Event handlers | `handle` prefix | `handleDelete` |
| Custom hooks | `use` prefix | `useAuth`, `useTheme` |
| Constants | `UPPER_SNAKE_CASE` | `API_URL`, `ROUTES` |
| Store hooks | `use<Name>Store` | `useAuthStore` |

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
    services/     # Business logic (jwt, mfa, oauth2, api_key, audit)
  tests/
    unit/         # Isolated per-module tests
    integration/  # Cross-module tests
    conftest.py   # Shared fixtures

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
