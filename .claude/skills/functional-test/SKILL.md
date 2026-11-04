---
name: functional-test
description: Record and run functional and end-to-end tests with Playwright. Allows functional teams to record new user flows with codegen (generating Playwright specs and Markdown scenario cards), and developers/QA to list and run tests in headless mode (anti-regression), headed mode, or interactive UI mode (--ui).
---

# Functional & Anti-Regression Test Skill (Playwright)

This skill unifies the lifecycle of user flow testing:
1. **Recording & Documentation**: Functional analysts or QA record real user flows on screen using `playwright codegen`, generating both the automated test script and a Markdown scenario card.
2. **Execution & Anti-Regression**: Anyone (developers during local development, CI, QA) can run the recorded test suite in headless mode (fast anti-regression), headed mode (`--headed`), or via the interactive Playwright Test Runner (`--ui`).

Do not simulate recordings, invent expected results, or report a test as passing if it was not successfully executed.

---

## Commands

- `/functional-test`: Guided mode (prompts to record a new test, list scenarios, or run tests).
- `/functional-test new` (or `record` / `nuovo`): Records and documents a new user scenario.
- `/functional-test list` (or `elenco`): Displays a summary table of all recorded scenarios and their latest execution status.
- `/functional-test run [id | all]` (or `esegui`): Runs a specific scenario or the entire suite in default headless mode (fast, ideal for anti-regression loops).
- `/functional-test run [id | all] --headed`: Runs the test visibly on screen with a real Chromium browser window.
- `/functional-test run [id | all] --ui`: Launches the interactive Playwright Test Runner UI (time-travel debugging, step-by-step playback, DOM inspection).

---

## Workspace & File Paths

- **Workspace**: `frontend/`. All Playwright and npm commands must be executed from `frontend/`.
- **Test Scripts**: `frontend/tests/functional/<id>.spec.ts`
- **Scenario Cards**: `frontend/tests/functional/scenarios/<id>.md`
- **Playwright Configuration**: `frontend/playwright.functional.config.ts`

---

## Automated Environment Management

AuthGlow functional tests exercise the real application. Before recording with `codegen` or executing tests, automatically verify and prepare the environment.

### 1. Backend Health Check (Port 8001)
Check if the backend is running and responsive:
```bash
curl -s http://localhost:8001/api/meta
```

If the call fails or connection is refused, start the backend in the background in **Demo Mode** with isolated ephemeral storage (execute from `backend/`):
```bash
rm -rf /tmp/authglow-demo && mkdir -p /tmp/authglow-demo/storage /tmp/authglow-demo/keys

STORAGE_PATH=/tmp/authglow-demo/storage \
KEYS_DIR=/tmp/authglow-demo/keys \
SECRET_KEY=demo-secret-key-that-is-at-least-32-chars-long! \
DEMO_MODE=true \
python3 -m uvicorn main:app --port 8001
```
Wait until `http://localhost:8001/api/meta` returns HTTP 200 before continuing.

### 2. Frontend Health Check (Port 5173)
For `codegen` or `--ui` mode, ensure the Vite development server is running:
```bash
curl -s http://localhost:5173/ > /dev/null || (cd frontend && npm run dev &)
```
*(For headless or headed test execution, `playwright.functional.config.ts` automatically manages the dev server via its `webServer` block).*

---

## 1. List Scenarios (`/functional-test list`)

1. Read all files in `frontend/tests/functional/scenarios/*.md`.
2. Extract:
   - **ID**
   - **Title**
   - **Objective**
   - **Status** (e.g. *passed*, *failed*, *pending*)
   - **Last Execution Date** (from the `## Last Execution` section)
3. Display a clean Markdown table. If no scenario cards exist, notify the user that no scenarios have been registered yet and propose creating one with `/functional-test new`.

---

## 2. New Scenario Recording (`/functional-test new`)

### Step 2.1: Collect Scenario Details
Use the question tool to gather any missing information:
- **ID**: Short alphanumeric identifier (e.g. `invalid-login`, `create-api-key`, matching `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`).
- **Objective**: What the user should achieve or verify (used as brief title).
- **Initial URL**: Default `http://localhost:5173/auth/login` (or specific page).
- **Expected Results**: Visible UI elements, success notifications, specific URLs, or expected error messages.
- **Preconditions**: Test credentials, required data, or initial application state.

Verify that neither `frontend/tests/functional/<id>.spec.ts` nor `frontend/tests/functional/scenarios/<id>.md` already exists. In case of collision, prompt for a different ID or explicit overwrite permission.

### Step 2.2: Live Screen Recording (Codegen)
1. Ensure backend and frontend are running (see Automated Environment Management).
2. Explain to the user that a Chromium window and Playwright Inspector will open. The user performs the actions manually and closes the browser window upon completion.
3. Launch codegen targeting a unique temporary file outside the repository:
   ```bash
   npx playwright codegen --browser chromium --target playwright-test --output "/tmp/codegen-<id>.ts" "<initial-url>"
   ```
4. Await completion and read the generated temporary file. If the process remains open, ask the user to confirm completion before reading.

### Step 2.3: Script Refinement & Scenario Card
Inspect the generated code:
- Format the test using `test` and `expect` from `@playwright/test`.
- Prefer resilient selectors: accessible roles (`getByRole`), labels (`getByLabel`), or `getByTestId`.
- **Add auto-waiting assertions**:
  - Success verification: `await expect(page.getByRole(...)).toBeVisible()`, `await expect(page).toHaveURL(...)`.
  - Error messages: `await expect(page.getByRole('alert')).toContainText('...')`.
- Strip any accidentally typed sensitive values (replace with test constants or environment variables).
- Save the refined script to `frontend/tests/functional/<id>.spec.ts`.
- Create the scenario card in `frontend/tests/functional/scenarios/<id>.md`:

```markdown
# <id> - <title>

- ID: <id>
- Title: <title>
- Objective: <objective>
- Initial URL: <initial-url>
- Script: tests/functional/<id>.spec.ts
- Status: pending

## Preconditions
<environment, test account, or required initial data>

## Steps
<numbered steps derived from the recording>

## Expected Results
<positive checks and expected error messages>

## Last Execution
Not executed yet.
```

### Step 2.4: Validation Run
Immediately run the newly created test to confirm script stability:
```bash
npx playwright test tests/functional/<id>.spec.ts --config playwright.functional.config.ts
```
Update the scenario card with the actual outcome and remove `/tmp/codegen-<id>.ts`.

---

## 3. Test Execution (`/functional-test run [id | all]`)

This mode serves both functional testers re-verifying business flows and developers running anti-regression checks.

### Parameters & Execution Modes:
- If ID is omitted, prompt whether to run a specific test (listing available IDs) or `all`.
- **Default Headless Mode**:
  ```bash
  npx playwright test tests/functional/<id>.spec.ts --config playwright.functional.config.ts
  ```
  *(To run all scenarios: omit the spec path)*
- **Headed Mode (`--headed`)**:
  ```bash
  npx playwright test tests/functional/<id>.spec.ts --config playwright.functional.config.ts --headed
  ```
- **Interactive UI Mode (`--ui`)**:
  ```bash
  npx playwright test tests/functional/<id>.spec.ts --config playwright.functional.config.ts --ui
  ```

### Scenario Card Update & Reporting:
1. When execution completes, update the `## Last Execution` section in `frontend/tests/functional/scenarios/<id>.md`:
   - Date, timestamp, and timezone.
   - Status: **passed** or **failed**.
   - Specific failure details (locator timeout, assertion mismatch) if failed.
2. Present a clear execution summary:
   - Total elapsed time.
   - List of passed and failed tests.
   - If a test failed, provide the failing step, assertion, and timeout locator.
3. Suggest next steps:
   - Run another scenario.
   - Keep dev servers active for manual exploration at `http://localhost:5173`.
   - Shut down background services using the `stop-services` skill (`/stop-services 8001 5173`).
