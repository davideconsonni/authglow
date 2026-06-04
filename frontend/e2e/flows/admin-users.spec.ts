import { test, expect } from '@playwright/test'

test.describe('Admin — Search user → Toggle active → View detail', () => {
  test('search for a user, toggle active status, and view detail drawer', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('[data-testid="user-search-input"]')).toBeVisible()

    // Search
    await page.fill('[data-testid="user-search-input"]', 'admin')
    await page.keyboard.press('Enter')
    await page.waitForTimeout(1000)

    const rows = page.locator('[data-testid="user-table-row"]')
    const rowCount = await rows.count()

    if (rowCount > 0) {
      // Toggle active status
      const toggleBtn = rows.first().locator('[data-testid="toggle-active-btn"]')
      if (await toggleBtn.isVisible()) {
        await toggleBtn.click()
        await page.waitForTimeout(500)
      }

      // View detail drawer by clicking the user row
      await rows.first().click()
      await page.waitForTimeout(500)
      await expect(page.locator('[data-testid="user-detail-drawer"]')).toBeVisible({ timeout: 3000 })

      // Close drawer
      await page.locator('[data-testid="user-detail-drawer"] button').first().click()
      await page.waitForTimeout(300)
    }
  })
})
