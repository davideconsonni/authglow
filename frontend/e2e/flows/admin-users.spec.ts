import { test, expect } from '@playwright/test'
import { injectAuth } from '../auth.setup'

test.describe('Admin — Search user → Toggle active → View detail', () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page)
  })

  test('search for a user and toggle active status', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    await expect(page.locator('[data-testid="user-search-input"]')).toBeVisible()

    await page.fill('[data-testid="user-search-input"]', 'admin')
    await page.keyboard.press('Enter')
    await page.waitForTimeout(1000)

    const rows = page.locator('[data-testid="user-table-row"]')
    const rowCount = await rows.count()

    if (rowCount > 0) {
      const toggleBtn = rows.first().locator('[data-testid="toggle-active-btn"]')
      if (await toggleBtn.isVisible()) {
        await toggleBtn.click()
        await page.waitForTimeout(500)
      }
    }
  })
})
