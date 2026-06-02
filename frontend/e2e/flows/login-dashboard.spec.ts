import { test, expect } from '@playwright/test'
import { injectAuth, clearAuth } from '../auth.setup'

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

  test('logout clears session and redirects to login', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    await clearAuth(page)
    await page.goto('/dashboard')
    await page.waitForURL('**/auth/login')
    await expect(page).toHaveURL(/\/auth\/login/)
  })
})
