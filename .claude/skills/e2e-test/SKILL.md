---
name: e2e-test
description: Run end-to-end (E2E) tests with Playwright in frontend/e2e. Allows selecting a specific test flow (or the full suite) and execution mode (headless terminal, headed browser on screen, or interactive --ui mode with time-travel debugging).
---

# E2E Test Skill (Playwright)

This skill automates running AuthGlow end-to-end (E2E) tests with Playwright. It transparently handles starting the backend in Demo Mode with clean ephemeral storage and lets the user choose their preferred execution and visualization mode.

## Commands

- `/e2e-test`: Starts guided mode (prompts for test selection and execution mode).
- `/e2e-test <test-name>`: Runs the specified test in default headless mode (e.g. `/e2e-test api-keys`).
- `/e2e-test <test-name> --headed`: Runs the test visibly on screen with a real Chromium browser window.
- `/e2e-test <test-name> --ui`: Launches the interactive Playwright Test Runner UI.
- `/e2e-test all`: Runs the entire E2E test suite.

---

## 1. Available E2E Flows

Specs are located in `frontend/e2e/flows/` (and mobile in `frontend/e2e/mobile/`):

| Identifier | Spec File | Description |
|------------|-----------|-------------|
| `api-keys` | `e2e/flows/api-keys.spec.ts` | API key creation, BOPLA scope filtering, edit description, revocation |
| `login-dashboard` | `e2e/flows/login-dashboard.spec.ts` | OAuth2 PKCE login, dashboard stats, navigation |
| `admin-users` | `e2e/flows/admin-users.spec.ts` | User management, RBAC roles and permissions assignment |
| `admin-bulk` | `e2e/flows/admin-bulk.spec.ts` | Bulk operations (user suspension, bulk deletion, CSV export) |
| `oauth-clients` | `e2e/flows/oauth-clients.spec.ts` | OAuth2 client creation and claim policy configuration |
| `device-authorization` | `e2e/flows/device-authorization.spec.ts` | Device Authorization Grant flow (RFC 8628, user code verification) |
| `playground-full-flow` | `e2e/flows/playground-full-flow.spec.ts` | Interactive OAuth2 Playground flow |
| `zitadel-federation` | `e2e/flows/zitadel-federation.spec.ts` | Zitadel federation provider integration flow |
| `federation-oauth2` | `e2e/flows/federation-oauth2.spec.ts` | Generic OIDC/OAuth2 federation flow |
| `mobile-layout` | `e2e/mobile/mobile-layout.spec.ts` | Mobile responsive layout and drawer verification |
| `all` | `e2e/flows/*.spec.ts` | Run all E2E specs |

---

## 2. Execution Modes

1. **Headless (Terminal)**:
   - Runs in background without opening browser windows.
   - Fast and concise; prints status and elapsed time.
2. **Headed (`--headed`)**:
   - Opens a real Chromium window on the desktop.
   - Displays live automation steps (typing, clicking, form submission) on screen.
3. **Interactive (`--ui`)**:
   - Launches the full **Playwright Test Runner UI**.
   - Enables time-travel debugging, DOM inspection, locator validation, network request logs, and step-by-step playback.

---

## 3. Prerequisite Management (Automated)

AuthGlow E2E tests require an authenticated session generated in `global.setup.ts`. The agent must verify and prepare the environment before running tests.

### Step 3.1: Check Backend (port 8001)
Check if the backend is already running and in demo mode:
```bash
curl -s http://localhost:8001/api/meta
```

If the call fails or connection is refused, start the backend in the background with isolated ephemeral storage:
```bash
# Clean temporary storage to prevent crypto conflicts (InvalidTag)
rm -rf /tmp/authglow-demo && mkdir -p /tmp/authglow-demo/storage /tmp/authglow-demo/keys

# Start backend via uvicorn in background
STORAGE_PATH=/tmp/authglow-demo/storage \
KEYS_DIR=/tmp/authglow-demo/keys \
SECRET_KEY=demo-secret-key-that-is-at-least-32-chars-long! \
DEMO_MODE=true \
python3 -m uvicorn main:app --port 8001
```
*(Execute from the `backend/` directory).*

Wait until `http://localhost:8001/api/meta` returns HTTP 200 before proceeding.

### Step 3.2: Check Frontend (port 5173)
If `--ui` mode is selected, ensure the Vite dev server is running so the browser can immediately render pages:
```bash
curl -s http://localhost:5173/ > /dev/null || (cd frontend && npm run dev &)
```
*(For headless or headed mode, `playwright.config.ts` automatically manages the dev server via its `webServer` block).*

---

## 4. Test Execution

All commands must be executed from `frontend/`.

### Headless Mode
```bash
npx playwright test <spec-path> --project=chromium
```
Example:
```bash
npx playwright test e2e/flows/api-keys.spec.ts --project=chromium
```

### Headed Mode (`--headed`)
```bash
npx playwright test <spec-path> --headed --project=chromium
```

### Interactive Mode (`--ui`)
Run in background so the UI process remains active on the user's screen:
```bash
npx playwright test <spec-path> --ui
```
Inform the user that the Playwright Test Runner is open and ready to run or step through actions.

---

## 5. Report and Cleanup

1. Report the test result clearly:
   - Total execution time.
   - List of passed / failed tests.
   - If a test failed, provide the specific error message and locator that timed out.
2. Offer next steps:
   - Run another test.
   - Keep the servers running for manual testing in the browser (`http://localhost:5173/auth/login`).
   - Stop local background services using the `stop-services` skill (`/stop-services 8001 5173`).
