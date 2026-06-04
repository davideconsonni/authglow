import { type Page, type BrowserContext } from '@playwright/test'

const BASE_URL = 'http://localhost:5173'

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
  password = 'AdminP@ss123!',
) {
  await page.goto('/auth/login')
  await page.waitForLoadState('networkidle')
  await page.fill('[data-testid="login-email"]', email)
  await page.fill('[data-testid="login-password"]', password)
  await page.click('[data-testid="login-submit"]')
  await page.waitForURL('**/dashboard')
  await page.waitForLoadState('networkidle')
}
