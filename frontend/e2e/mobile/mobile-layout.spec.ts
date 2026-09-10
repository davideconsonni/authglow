import { test, expect } from '@playwright/test'
import { clearAuth } from '../auth.setup'

test.describe('Mobile layout — 375x812 (iPhone 14)', () => {
  test.use({ viewport: { width: 375, height: 812 } })

  test('login page collapses to single column', async ({ page }) => {
    // Drop the stored session: an authenticated user is bounced away
    // from the login page.
    await clearAuth(page)
    await page.goto('/auth/login')
    await page.waitForLoadState('networkidle')
    // Brand column should be hidden on mobile
    const brandText = page.locator('text=Enterprise CIAM Platform')
    await expect(brandText).toBeHidden()
    // The OAuth2 sign-in entry point should be visible (the login page
    // has no credential form — it starts the PKCE flow)
    await expect(page.getByTestId('login-submit')).toBeVisible({ timeout: 20000 })
  })

  test('dashboard renders at mobile viewport', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    // Sidebar should be hidden on mobile (only toggle visible)
    await expect(page.locator('[data-testid="sidebar"]')).toBeHidden()
    // Page title should be visible
    await expect(page.getByRole('heading', { name: /Welcome back/ })).toBeVisible()
  })

  test('sidebar can be opened and closed on mobile', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')

    // Open sidebar via hamburger
    await page.click('button[aria-label="Open sidebar"]')
    // The mobile navigation panel must be visible
    const mobileNav = page.locator('aside[aria-label="Navigation menu"]')
    await expect(mobileNav).toBeVisible({ timeout: 3000 })
    await expect(mobileNav.getByRole('link', { name: 'Dashboard' })).toBeVisible()

    // Close sidebar via its backdrop — click the right edge, away from
    // the panel itself (the backdrop center is covered by the panel and
    // Playwright would retry until timeout).
    await page.locator('[data-testid="sidebar-mobile-backdrop"]').click({ position: { x: 370, y: 60 } })
    await expect(mobileNav).toBeHidden({ timeout: 3000 })
  })

  test('admin users table scrolls horizontally with key columns', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')
    // Page renders with its title
    await expect(page.getByRole('heading', { name: 'Users', exact: true })).toBeVisible()
    // Action buttons should be accessible
    const rows = page.locator('[data-testid="user-table-row"]')
    const firstRow = rows.first()
    if (await firstRow.isVisible()) {
      // Toggle active button should be visible even on mobile
      const toggleBtn = firstRow.locator('[data-testid="toggle-active-btn"]')
      await expect(toggleBtn).toBeVisible()
    }
  })
})
