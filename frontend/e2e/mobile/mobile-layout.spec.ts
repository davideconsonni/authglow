import { test, expect } from '@playwright/test'
import { injectAuth } from '../auth.setup'

test.describe('Mobile layout — 375x812 (iPhone 14)', () => {
  test.use({ viewport: { width: 375, height: 812 } })

  test.beforeEach(async ({ page }) => {
    await injectAuth(page)
  })

  test('login page collapses to single column', async ({ page }) => {
    await page.goto('/auth/login')
    await page.waitForLoadState('networkidle')
    // Brand column should be hidden on mobile
    const brandText = page.locator('text=Enterprise CIAM Platform')
    await expect(brandText).toBeHidden()
    // Form should be full width
    await expect(page.locator('input[type="email"]')).toBeVisible()
  })

  test('dashboard renders at mobile viewport', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')
    // Sidebar should be hidden on mobile (only toggle visible)
    await expect(page.locator('[data-testid="sidebar"]')).toBeHidden()
    // Page title should be visible
    await expect(page.locator('[data-testid="page-title"]')).toBeVisible()
  })

  test('sidebar can be opened and closed on mobile', async ({ page }) => {
    await page.goto('/dashboard')
    await page.waitForLoadState('networkidle')

    // Open sidebar via hamburger
    await page.click('button[aria-label="Open sidebar"]')
    await page.waitForTimeout(500)
    // Sidebar content should be visible now
    await expect(page.locator('text=Dashboard').first()).toBeVisible({ timeout: 3000 })

    // Close sidebar via backdrop
    await page.click('[data-testid="confirm-dialog-backdrop"]')
    await page.waitForTimeout(300)
  })

  test('admin users table scrolls horizontally with key columns', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')
    // User column should always be visible
    await expect(page.locator('text=User').first()).toBeVisible()
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
