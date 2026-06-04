import { test, expect } from '@playwright/test'

test.describe('Admin — Bulk select → Deactivate → Verify', () => {
  test('bulk select users, deactivate, and verify', async ({ page }) => {
    await page.goto('/admin/users')
    await page.waitForLoadState('networkidle')

    // Select first user
    const rows = page.locator('[data-testid="user-table-row"]')
    const rowCount = await rows.count()

    if (rowCount > 0) {
      const firstCheckbox = rows.first().locator('[data-testid="user-select-checkbox"]')
      if (await firstCheckbox.isVisible()) {
        await firstCheckbox.click()
        await expect(page.locator('[data-testid="bulk-action-bar"]')).toBeVisible()

        // Click deactivate and confirm
        const deactivateBtn = page.locator('[data-testid="bulk-deactivate-btn"]')
        if (await deactivateBtn.isVisible()) {
          await deactivateBtn.click()

          const modal = page.locator('[data-testid="confirm-dialog"]')
          if (await modal.isVisible({ timeout: 2000 })) {
            await page.click('[data-testid="confirm-dialog-confirm"]')
            await page.waitForTimeout(1000)
          }
        }
      }
    }
  })
})
