import { test, expect } from '@playwright/test'
import { injectAuth } from '../auth.setup'

test.describe('Admin — Bulk select → Deactivate → Verify', () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page)
  })

  test('bulk select users and cancel', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    const rows = page.locator('[data-testid="user-table-row"]')
    const rowCount = await rows.count()

    if (rowCount > 0) {
      const firstCheckbox = rows.first().locator('[data-testid="user-select-checkbox"]')
      if (await firstCheckbox.isVisible()) {
        await firstCheckbox.click()

        await expect(page.locator('[data-testid="bulk-action-bar"]')).toBeVisible()

        const deactivateBtn = page.locator('[data-testid="bulk-deactivate-btn"]')
        if (await deactivateBtn.isVisible()) {
          await deactivateBtn.click()

          const modal = page.locator('[data-testid="confirm-dialog"]')
          if (await modal.isVisible({ timeout: 2000 })) {
            await page.click('[data-testid="confirm-dialog-cancel"]')
          }
        }
      }
    }
  })
})
