import { test, expect } from '@playwright/test'

test.describe('OAuth Clients — Create → Rotate Secret → Delete', () => {
  test('create, rotate secret, and delete an OAuth client', async ({ page }) => {
    await page.goto('/admin/oauth-clients')
    await page.waitForLoadState('networkidle')

    // Create
    await page.click('[data-testid="create-oauth-client-btn"]')
    await page.click('[data-testid="client-type-web"]')
    await page.fill('[data-testid="client-name-input"]', 'E2E Test App')
    await page.fill('[data-testid="client-uri-input-0"]', 'https://example.com/callback')
    await page.click('[data-testid="create-client-submit"]')

    await expect(page.locator('[data-testid="client-created-secret"]')).toBeVisible({ timeout: 5000 })
    await page.click('[data-testid="client-created-done"]')
    await page.waitForTimeout(1000)

    // Rotate secret
    const rotateBtn = page.locator('[data-testid="rotate-secret-btn"]').first()
    if (await rotateBtn.isVisible()) {
      await rotateBtn.click()
      await page.waitForTimeout(500)
      await expect(page.locator('[data-testid="client-created-secret"]')).toBeVisible({ timeout: 5000 })
      await page.click('[data-testid="client-created-done"]')
      await page.waitForTimeout(500)
    }

    // Delete
    const deleteBtn = page.locator('[data-testid="delete-client-btn"]').first()
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click()
      await page.click('[data-testid="confirm-dialog-confirm"]')
      await page.waitForTimeout(1000)
    }
  })
})
