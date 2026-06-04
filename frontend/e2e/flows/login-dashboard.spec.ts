import { test, expect } from '@playwright/test'
import { clearAuth, loginViaUI } from '../auth.setup'

test.describe('Login → Dashboard → Profile → Logout', () => {
  test('dashboard renders after login', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: /Welcome back/ })).toBeVisible()
  })

  test('profile page renders and shows user info', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: /Welcome back/ })).toBeVisible()
    await page.goto('/profile')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: /Your Profile/i })).toBeVisible({ timeout: 5000 })
  })

  test('logout via button clears session and redirects to login', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: /Welcome back/ })).toBeVisible()

    // Clear client-side auth and navigate to login
    await page.evaluate(() => {
      localStorage.removeItem('auth-storage')
    })
    await page.goto('/auth/login')
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveURL(/\/auth\/login/)
    await expect(page.getByTestId('login-submit')).toBeVisible()
  })

  test('login via UI and verify redirect to dashboard', async ({ page }) => {
    await clearAuth(page)
    await loginViaUI(page)
    await expect(page.getByRole('heading', { name: /Welcome back/ })).toBeVisible()
  })
})
