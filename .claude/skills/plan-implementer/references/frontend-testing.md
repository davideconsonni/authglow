# Frontend Testing

Quando e come usare Vitest vs Playwright per i task frontend. Da consultare nella Fase 5 della skill.

## Decision tree rapido

```
Modifico un componente React isolato (form, button, page)?
    ├─ Sì, e non interagisce con API/store globali → Vitest (unit)
    └─ Coinvolge store/API → Vitest + mock minimo

Modifico un hook custom?
    └─ Vitest (renderHook) con mock dei selettori Zustand / api

Modifico api.ts o uno store Zustand?
    ├─ Vitest per il modulo
    └─ Playwright: 1 spec che esercita il flusso che lo usa

Modifico routing, auth flow, MFA, OAuth2, federated login?
    └─ Playwright (E2E) obbligatorio

Modifico un layout / css / design tokens?
    └─ Visual check manuale (Playwright screenshot opzionale per regression)
```

## Comandi

cwd = `frontend/`

| Tipo | Comando | Quando |
|---|---|---|
| Vitest singolo file | `npm test -- src/components/Auth/LoginForm.test.tsx` | Sviluppo |
| Vitest singolo test | `npm test -- src/components/Auth/LoginForm.test.tsx -t "shows error"` | Singolo caso |
| Vitest tutti | `npm test` | Prima di commit (raro in dev) |
| Lint | `npm run lint` | Dopo test verdi |
| Build (type-check + bundle) | `npm run build` | Sanity check |
| Playwright tutti | `npx playwright test` | Pre-commit, modifica cross-cutting |
| Playwright singolo spec | `npx playwright test e2e/flows/login-dashboard.spec.ts` | Sviluppo |
| Playwright headed (debug) | `npx playwright test e2e/flows/login.spec.ts --headed` | Quando il test fallisce e vuoi vedere |

## Helpers Playwright (da `frontend/e2e/auth.setup.ts`)

```typescript
import { injectAuth, clearAuth, loginViaUI } from './auth.setup'

// Inietta auth bypassando la UI (per test che partono da "utente loggato")
await injectAuth(page, { userId: '...', scopes: ['read'] })

// Pulisci auth (per test che partono da "non loggato")
await clearAuth(page)

// Flusso UI completo (più lento ma più realistico)
await loginViaUI(page, email, password)
```

**Regola**: per test di feature che richiedono auth, usa `injectAuth()` (veloce) per setup; usa `loginViaUI()` solo per i test del flusso di login stesso.

## Selettori stabili

| Tipo | Esempio | Note |
|---|---|---|
| `data-testid` | `page.getByTestId('login-submit')` | **Scegli questo di default** |
| `role` | `page.getByRole('button', { name: 'Login' })` | Per a11y + semantic |
| Text | `page.getByText('Welcome')` | Solo se univoco |
| CSS | `page.locator('.login-form button')` | Evita, fragile |

Convenzioni:
- Aggiungi `data-testid` SOLO se serve per test E2E o per query DOM che non hanno un selettore semantico
- Non rimuovere `data-testid` esistenti senza verificare che nessun test lo usi
- `role="alert"` su messaggi di errore → `page.getByRole('alert')` per asserzioni

## Pattern Vitest comuni

### Componente con form

```typescript
import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { LoginForm } from './LoginForm'

describe('LoginForm', () => {
  it('shows error on invalid credentials', async () => {
    const user = userEvent.setup()
    render(<LoginForm onSubmit={vi.fn()} />)

    await user.type(screen.getByLabelText('Email'), 'wrong@example.com')
    await user.type(screen.getByLabelText('Password'), 'bad')
    await user.click(screen.getByRole('button', { name: 'Login' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/invalid/i)
  })
})
```

### Hook Zustand

```typescript
import { renderHook, act } from '@testing-library/react'
import { useAuthStore } from '@/stores/authStore'

describe('useAuthStore', () => {
  beforeEach(() => {
    useAuthStore.getState().reset()
  })

  it('clears tokens on logout', () => {
    const { result } = renderHook(() => useAuthStore())
    act(() => result.current.logout())
    expect(result.current.accessToken).toBeNull()
  })
})
```

### API con mock

```typescript
import { vi } from 'vitest'
import { api } from '@/lib/api'

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}))

it('fetches user on mount', async () => {
  vi.mocked(api.get).mockResolvedValue({ id: '1', email: 'a@b.c' })
  // ...
})
```

## Pattern Playwright comuni

### Login + dashboard

```typescript
import { test, expect } from '@playwright/test'
import { injectAuth } from './auth.setup'

test('user lands on dashboard after login', async ({ page }) => {
  await page.goto('/auth/login')
  await injectAuth(page, { userId: 'user-1' })
  await page.goto('/dashboard')

  await expect(page.getByTestId('dashboard-header')).toBeVisible()
})
```

### Form submission con errore

```typescript
test('shows inline error on bad password', async ({ page }) => {
  await page.goto('/auth/login')

  await page.getByLabel('Email').fill('user@example.com')
  await page.getByLabel('Password').fill('wrongpass')
  await page.getByTestId('login-submit').click()

  await expect(page.getByRole('alert')).toContainText(/invalid/i)
})
```

## Anti-pattern frontend testing

| Anti-pattern | Perché evitarlo | Alternativa |
|---|---|---|
| `await page.waitForTimeout(2000)` | Flaky, lento | `await page.waitForSelector(...)` o `await expect(...).toBeVisible()` |
| Selettori CSS `.btn-primary` | Fragile a refactor | `data-testid` o `getByRole` |
| Test che dipendono da altri test | Ordine-dipendente, fragile | Ogni test setup autonomo |
| `page.click('.btn')` quando esistono 5 `.btn` | Ambiguo | `getByRole` o `getByTestId` |
| Snapshot test di intere page | Cambi un CSS, fallisce 50 test | Snapshot solo di componenti piccoli e stabili |
| Mock globale di `Date.now()` | Rischio di leak tra test | `vi.useFakeTimers()` + `vi.setSystemTime()` scoped |
| Login via UI in TUTTI i test | Lento (ogni test 5s in più) | `injectAuth()` per setup |
| Test E2E che asseriscono dettagli implementativi | Fragile | Asserisci comportamento utente osservabile |
| `try/catch` su Playwright assertions | Maschera fallimenti | Lascia che l'assertion fallisca naturalmente |

## Quando ESCLUDERE E2E

- Modifica a un singolo componente senza side-effect su routing/auth
- Modifica a CSS puro / design tokens (preferisci visual review)
- Modifica a types/interfaces (TypeScript ti copre)
- Refactor interno (test esistenti devono passare invariati)

## Quando INCLUDERE E2E

- Cambio al flusso di autenticazione (login, logout, MFA verify)
- Cambio a OAuth2 authorize/consent/token
- Cambio a federated login callback
- Cambio a password reset / change email
- Cambio a registrazione
- Cambio a gestione sessione (refresh, scadenza)

## Setup environment

Prima del primo E2E:

```bash
# Backend deve essere running su localhost:8000 (o configurato)
# Frontend dev server su localhost:5173
# Database/file storage pulito (test fixtures)

cd frontend
npm install
npx playwright install chromium   # solo prima volta
```

Per E2E paralleli: il `playwright.config.ts` ha `workers: 1` di default. Non aumentare a meno che i test non siano isolati.

## Output del test run

Quando lanci Playwright, ottieni:
- `playwright-report/` con HTML report
- `test-results/` con trace per ogni failure
- Screenshot/video catturati automaticamente on-failure

Per ispezionare un failure:
```bash
npx playwright show-report
npx playwright test e2e/flows/login.spec.ts --trace on
```

## Fixture esistenti utili

In `frontend/e2e/auth.setup.ts`:
- `injectAuth(page, { userId, scopes })` — bypass login
- `clearAuth(page)` — logout
- `loginViaUI(page, email, password)` — flusso completo

In `frontend/tests/` (Vitest):
- `@testing-library/react` per render
- `@testing-library/user-event` per interazione realistica
- `msw` (se presente) per mock API a livello network

## Convenzioni naming test file

| Tipo | Pattern | Esempio |
|---|---|---|
| Vitest unit | `kebab-case.test.ts(x)` co-located con il file testato | `src/components/LoginForm.test.tsx` |
| Vitest integration | `kebab-case.test.ts(x)` in `tests/` o co-located | `src/stores/authStore.test.ts` |
| Playwright spec | `kebab-case.spec.ts` in `e2e/flows/` | `e2e/flows/login-dashboard.spec.ts` |
| Test E2E setup | `auth.setup.ts` (esiste già) | |

## Riepilogo regola d'oro

- **Cambi 1-2 file isolati** → Vitest mirato
- **Cambi API/store/hook** → Vitest + 1 Playwright se il flusso è critico
- **Cambi auth/oauth/MFA/registration** → Playwright obbligatorio
- **Cambi layout/CSS** → visual check, Playwright screenshot opzionale
- **Suite completa frontend** → solo pre-commit, non a ogni item
