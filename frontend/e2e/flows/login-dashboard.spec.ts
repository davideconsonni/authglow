import { test, expect } from '@playwright/test'
import { injectAuth, clearAuth, loginViaUI } from '../auth.setup'

test.describe('Login → Dashboard → Profile → Logout', () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page)
  })

  test('dashboard renders after login', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-testid="page-title"]')).toBeVisible()
    await expect(page.locator('[data-testid="sidebar"]')).toBeVisible()
  })

  test('profile page renders and shows user info', async ({ page }) => {
    await page.goto('/profile')
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-testid="page-title"]')).toContainText('Profile')
  })

  test('logout via button clears session and redirects to login', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')

    // Open user dropdown menu and click logout
    await page.click('text=admin')
    await page.click('[data-testid="logout-btn"]')
    await page.waitForURL('**/auth/login')
    await expect(page).toHaveURL(/\/auth\/login/)
  })

  test('login via UI and verify redirect to dashboard', async ({ page }) => {
    await clearAuth(page)
    await loginViaUI(page)
    await expect(page.locator('[data-testid="page-title"]')).toBeVisible()
  })
})
