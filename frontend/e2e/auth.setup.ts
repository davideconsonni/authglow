import { type Page, type BrowserContext } from '@playwright/test'

const API_URL = 'http://localhost:8001'

interface AuthState {
  token: string
  user?: { id: string; email: string; scopes: string[] }
}

export async function injectAuth(page: Page, email = 'admin@example.com', password = 'AdminP@ss123!'): Promise<AuthState> {
  const response = await page.request.post(`${API_URL}/api/token`, {
    data: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password,
    }),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  })

  const body = await response.json()
  if (!response.ok()) {
    throw new Error(`Login failed: ${JSON.stringify(body)}`)
  }

  const token = body.access_token

  await page.evaluate((t) => {
    localStorage.setItem(
      'auth-storage',
      JSON.stringify({
        state: { token: t },
        version: 0,
      }),
    )
  }, token)

  return { token, user: body.user }
}

export async function clearAuth(page: Page) {
  await page.evaluate(() => localStorage.removeItem('auth-storage'))
}

export async function loginViaUI(page: Page, email = 'admin@example.com', password = 'AdminP@ss123!') {
  await page.goto('/auth/login')
  await page.waitForLoadState('networkidle')
  await page.fill('[data-testid="login-email"]', email)
  await page.fill('[data-testid="login-password"]', password)
  await page.click('[data-testid="login-submit"]')
  await page.waitForURL('**/dashboard')
  await page.waitForLoadState('networkidle')
}
