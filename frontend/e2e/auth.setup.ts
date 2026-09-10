import { type APIRequestContext, type Page } from '@playwright/test'

const BASE_URL = 'http://localhost:5173'
const API_URL = 'http://localhost:8001'

/**
 * Resolve the login password for the well-known demo admin.
 *
 * In demo mode the password rotates on every boot and is published via
 * `GET /api/meta` — read it there. The E2E fixture password only
 * applies to non-demo environments (or as a fallback if /api/meta is
 * unreachable).
 */
export async function getDemoPassword(): Promise<string> {
  try {
    const res = await fetch(`${API_URL}/api/meta`)
    const meta = (await res.json()) as {
      demo_mode?: boolean
      demo_user_password?: string
    }
    if (meta.demo_mode && meta.demo_user_password) {
      return meta.demo_user_password
    }
  } catch {
    // fall through to the fixture default
  }
  return 'AdminP@ss123!'
}

/**
 * Fetch a CSRF token bound to the request context's cookie session.
 *
 * Unsafe (POST/PUT/PATCH/DELETE) calls to cookie-authenticated backend
 * endpoints require the `X-CSRF-Token` header; the Playwright `request`
 * fixture shares cookies with the browser context but does not run the
 * SPA's api.ts, so specs must fetch the token themselves.
 */
export async function getCsrfToken(request: APIRequestContext): Promise<string> {
  const res = await request.get(`${API_URL}/api/oauth2/csrf-token`)
  const data = (await res.json()) as { csrf_token?: string }
  if (!res.ok() || !data.csrf_token) {
    throw new Error('Unable to fetch CSRF token for E2E API calls')
  }
  return data.csrf_token
}

export function csrfHeaders(csrf: string): Record<string, string> {
  // Only the token header: Playwright sets the right Content-Type
  // itself (json for `data`, urlencoded for `form`) — overriding it
  // with application/json breaks urlencoded form posts (422 missing
  // fields).
  return { 'X-CSRF-Token': csrf }
}

export async function clearAuth(page: Page) {
  await page.goto(BASE_URL)
  await page.waitForLoadState('networkidle')
  await page.evaluate(() => {
    localStorage.removeItem('auth-storage')
  })
}

export async function loginViaUI(
  page: Page,
  email = 'admin@example.com',
  password?: string,
) {
  const pwd = password ?? (await getDemoPassword())
  // Absolute URL: the global setup's manually-created page has no
  // config baseURL, so a relative path would be an invalid URL there.
  await page.goto(`${BASE_URL}/auth/login`)
  await page.waitForLoadState('networkidle')
  // The login page has no credential form: it starts the OAuth2
  // authorization-code + PKCE flow and redirects to the authorize
  // page, where the email/password form lives.
  await page.click('[data-testid="login-submit"]')
  await page.waitForURL('**/oauth2/authorize**')
  await page.fill('#oauth-email', email)
  await page.fill('#oauth-password', pwd)
  await page.getByRole('button', { name: /Sign In & Continue/ }).click()
  await page.waitForURL('**/dashboard')
  await page.waitForLoadState('networkidle')
}
