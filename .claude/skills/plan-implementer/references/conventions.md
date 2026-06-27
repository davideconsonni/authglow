# Convenzioni di codice (AuthGlow)

Riassunto compatto delle regole da `AGENTS.md`. Per i dettagli e i casi limite, **consulta sempre `AGENTS.md` direttamente** — questo file è solo un cheat sheet per non rileggerlo intero a ogni item.

## Comandi (in breve)

### Backend (cwd = `backend/`)

| Azione | Comando |
|---|---|
| Test mirato (singolo file) | `pytest tests/unit/test_<x>.py -q --tb=line` |
| Test mirato (singolo test) | `pytest tests/unit/test_<x>.py::Test<Y>::test_<z> -v` |
| Test paralleli (suite area) | `pytest tests/unit/<area> -q --tb=line -n auto` |
| Suite completa (solo per `core/`) | `pytest -q --tb=line -n auto` — `Bash timeout: 300000` |
| Lint | `ruff check authglow/` |
| Format | `ruff format authglow/` |
| Type check | `mypy authglow/` |
| Dev server | `uvicorn main:app --reload` |

### Frontend (cwd = `frontend/`)

| Azione | Comando |
|---|---|
| Test mirato (singolo file) | `npm test -- path/to/file` |
| Test (tutti) | `npm test` |
| Lint | `npm run lint` |
| Build (type-check + bundle) | `npm run build` |
| Dev server | `npm run dev` |
| E2E (tutti) | `npx playwright test` |
| E2E (singolo spec) | `npx playwright test e2e/flows/<file>.spec.ts` |

## Regola d'oro: test mirati, mai suite completa

Fai girare **solo i test dell'area toccata** durante lo sviluppo. La suite completa si lancia:
- Modifiche a `authglow/core/`
- Prima di un commit
- Una volta al termine di un item, per sanity check

## Python (backend)

### Import order (3 gruppi, blank line fra ognuno, ordine alfabetico)

```python
import os
from datetime import datetime

import bcrypt
from fastapi import APIRouter

from authglow.core.config import get_settings
```

- Moduli privati: leading underscore (`from authglow.core.config import _new_kid`)
- Lazy import dentro le funzioni per circular deps

### Tipi

- `typing` generics: `List[str]`, `Optional[str]`, `Dict[str, Any]`
- Built-in generics OK in codice nuovo: `list[str]`, `dict[str, object]`
- `Optional[X]`, non `X | None` (Python 3.11 compat)
- Return type annotation **richiesta** su tutte le funzioni
- Pydantic: annotazioni complete su tutti i campi, `Field(default_factory=...)` per default mutabili

### Naming

| Elemento | Convenzione | Esempio |
|---|---|---|
| Funzioni/metodi | `snake_case` | `get_current_user` |
| Funzioni private | `_leading_underscore` | `_derive_key` |
| Classi | `PascalCase` | `JWTService`, `UserStorage` |
| Modelli Pydantic | `PascalCase` + suffisso | `UserCreate`, `TokenData` |
| Costanti | `UPPER_SNAKE_CASE` | `PREFIX_LENGTH` |
| Costanti private | `_UPPER_SNAKE_CASE` | `_KEY_PREFIX` |
| Dependency injectors | `get_<name>` | `get_user_storage` |
| Test classi | `Test<Subject>` | `TestJWTTokenCreation` |
| Test metodi | `test_<scenario>` | `test_expired_token_rejected` |

### Error handling

- `HTTPException` con `status_code` e `detail` espliciti
- Eccezioni custom per domain logic (es. `APIKeyLockedException`)
- Catch in route handlers → traduci in `HTTPException`
- Path security-critical: `NoReturn` + `handle_failed_login()` per evitare user enumeration
- Usa costanti `status.HTTP_XXX_*`

### Logging

- **SOLO `structlog`**, mai `logging` stdlib
- Logger di default: `structlog.get_logger("authglow.audit")`
- Output JSON su stdout
- Maschera/hash PII basato su `audit_email_log_level`

### Pydantic

- Eredita da `pydantic.BaseModel`
- Request/response separati dai domain model (`UserCreate` vs `User`)
- `model_dump()` (non `.dict()`), `model_copy(update=...)` (non `.copy()`)
- `field_validator` per validazioni custom
- Settings: `pydantic_settings.BaseSettings` con `SettingsConfigDict`

### FastAPI

- `router = APIRouter()` per modulo, incluso in `main.py`
- DI: `Depends(get_<service_factory>)`
- Rate limit: `@limiter.limit("5/minute")` con `request: Request` come primo parametro
- Response model dichiarato: `response_model=UserResponse`
- Handler `async def`, chiamate servizi con `await`
- File I/O wrapped in `asyncio.to_thread()`

### Repository pattern (post-Fase 21)

- I service dipendono da `Protocol`, non dalle implementazioni
- Ctor: `repository=None`, fallback a `get_<entity>_repository()`
- Atomicità cross-entity **nei service**, non nei repo
- Aggiungere un backend (es. Postgres): 3 step — pip install, impl in `repositories/<backend>/`, factory in `repositories/dependencies.py`
- **CRITICO — lru_cache bypass**: `BaseFileRepository.__init__` chiama `authglow.repositories.file.base.get_settings()` (NON `authglow.core.config.get_settings`). Ogni factory in `repositories/dependencies.py` deve accettare `settings: Settings | None = None` e il service passa `self.settings` esplicitamente. Senza questo fix, i test condividono `_storage_path` e falliscono random.

### Test (pytest)

- `pytest-asyncio` con `asyncio_mode = "auto"` — niente `@pytest.mark.asyncio` per test
- Fixture: import dentro il body, `patch("authglow.*.get_settings")`
- `autouse` fixture per override settings in tutti i test
- Assert: plain `assert`, niente `self.assertEqual`
- `pytest.raises` per eccezioni
- Directory: `tests/unit/`, `tests/integration/`, `tests/conftest.py`
- 39 conformance tests in `tests/unit/repositories/test_protocols.py` — aggiungere 1 riga a `_IMPL_TABLE` per supportare nuova impl
- 7 in-memory smoke tests in `tests/unit/repositories/test_in_memory.py`

### Altro

- **UTC ovunque**: `utcnow()` da `authglow.core.datetime`
- **Segreti**: `secrets.token_urlsafe()` / `secrets.token_hex()`
- **Concurrency**: `named_lock()` da `authglow.core.concurrency`
- **Caching**: `functools.lru_cache` per funzioni pure, `cachetools.TTLCache` per TTL
- **Docstring**: modulo sempre; funzioni pubbliche in stile Google/NumPy

## TypeScript/React (frontend)

### Import order (3 gruppi)

```typescript
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'

import { api } from '@/lib/api'
import { cn } from '@/lib/utils'

import { Sibling } from './Sibling'
```

- `import type` per type-only (enforced by `verbatimModuleSyntax`)
- `@/` alias → `./src/*`
- NO barrel files / `index.ts` re-exports — import diretto per path

### Tipi

- `interface` per object shapes, `type` per union/derived
- Props interface: suffisso `Props` (`PageHeaderProps`)
- Generics nell'API layer: `api.get<AuthUser>(...)`
- Minimizza type assertions; preferisci narrowing

### Naming

| Elemento | Convenzione | Esempio |
|---|---|---|
| Component file | `PascalCase.tsx` | `LoginForm.tsx` |
| Non-component file | `camelCase.ts` | `authStore.ts` |
| UI primitive (shadcn) | `kebab-case.tsx` | `button.tsx` |
| Test file | `kebab-case.test.ts` | `phase2-auth.test.ts` |
| E2E spec | `kebab-case.spec.ts` | `login-dashboard.spec.ts` |
| Component | `PascalCase` | `StatusBadge` |
| Functions/hooks | `camelCase` | `useAuth`, `formatDate` |
| Event handlers | `handle` prefix | `handleDelete` |
| Custom hook | `use` prefix | `useAuth`, `useTheme` |
| Constanti | `UPPER_SNAKE_CASE` | `API_URL`, `ROUTES` |
| Store hook | `use<Name>Store` | `useAuthStore` |

### Componenti

- 100% functional components
- Named export (no default export tranne `App.tsx`)
- Props interface sopra al componente, destrutturato nei params
- Helper interni: `function Name()` non esportati
- `React.forwardRef` SOLO per shadcn primitives
- Code splitting: `React.lazy()` con `.then((m) => ({ default: m.ComponentName }))`

### State management

- **Zustand** per client state — separa `State` e `Actions` interfaces, interseca come `Store`
- Hooks di convenienza (`useAuth`) che wrappano selettori
- **TanStack Query** per server state — wrapper `useApiQuery` / `useApiMutation`
- Query keys: `string[]` con segmenti dinamici; conditional con `{ enabled }`

### Styling

- Tailwind utility in JSX `className`
- `cn()` (clsx + tailwind-merge) per conditional/merged classes
- Token via CSS variables: `text-text-primary`, `bg-surface-1`, `border-semantic-error`
- shadcn/ui: `class-variance-authority` (CVA) per varianti
- Pattern comuni: `rounded-xl`, `transition-colors`, `hover:scale-[1.02]`

### Forms

- `react-hook-form` + `zod`
- Schema a livello modulo, tipo via `z.infer<typeof schema>`
- `useForm<T>({ resolver: zodResolver(schema) })`
- Errori: `errors.fieldName && <p role="alert">{errors.fieldName.message}</p>`

### Test (Vitest + Playwright)

- Vitest: `import { describe, it, expect } from 'vitest'`
- Playwright: serial (`workers: 1`), projects: chromium + mobile
- Helpers in `auth.setup.ts`: `injectAuth()`, `clearAuth()`, `loginViaUI()`
- Selettori stabili: `data-testid`
- `role="alert"` su errori per a11y

## Anti-pattern da evitare (letti dai piani)

- `print(...)` al posto di `structlog` (VAPT-029, VAPT-083)
- Update services con `hasattr`/`setattr` alla cieca (VAPT-102, VAPT-103) → whitelist esplicita
- Confronto secret/hash con `==` o `!=` (VAPT-051) → `secrets.compare_digest` o `bcrypt.checkpw`
- `bcrypt.gensalt()` senza rounds espliciti (VAPT-038) → `bcrypt_rounds` setting + re-hash on login
- Test con secret hardcoded (AGENTS.md "Test fixtures") → riusa fixtures o `secrets.token_urlsafe()`
- Default `oauth2_client_secret` accettato in produzione (VAPT-014, VAPT-052) → hard-fail `is_production`
- Rate limit keys su IP raw dietro proxy (VAPT-025) → `ProxyHeadersMiddleware` con allowlist
- `Script-src 'unsafe-inline'` in CSP (VAPT-028) → rimuovere, spostare inline in file esterno
- Segreti in URL (VAPT-021, VAPT-022) → codice nel body, link pulito

## Segreti nei test — TL;DR

```python
# ❌ MAI
SECRET = "abc123def456ghi789jkl012mno345pq"

# ✅ Genera runtime
import secrets
fake_token = secrets.token_urlsafe(16)

# ✅ Riusa fixture esistente
def test_x(test_user, test_settings, mfa_service):
    ...
```

Se un nuovo pattern di test continua a triggerare gitleaks, aggiungi regex mirata a `backend/tests/.gitleaks.toml` con commento esplicativo del perché è safe.
