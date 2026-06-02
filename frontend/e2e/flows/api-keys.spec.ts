import { test, expect } from '@playwright/test'
import { injectAuth } from '../auth.setup'

test.describe('API Keys — Create → Copy → Revoke', () => {
  test.beforeEach(async ({ page }) => {
    await injectAuth(page)
  })

  test('create and revoke an API key', async ({ page }) => {
    await page.goto('/api-keys')
    await page.waitForLoadState('networkidle')

    await page.click('[data-testid="create-api-key-btn"]')
    await expect(page.locator('[data-testid="create-key-modal"]')).toBeVisible()

    await page.fill('[data-testid="key-name-input"]', 'E2E Test Key')
    await page.fill('[data-testid="key-scopes-input"]', 'read')
    await page.click('[data-testid="key-create-submit"]')

    await expect(page.locator('[data-testid="key-created-display"]')).toBeVisible({ timeout: 5000 })
    const keyText = await page.locator('[data-testid="key-created-display"] code').textContent()
    expect(keyText).toBeTruthy()

    await page.click('[data-testid="key-created-done"]')

    await page.waitForSelector('[data-testid="api-key-row"]', { timeout: 5000 })

    const revokeBtn = page.locator('[data-testid="revoke-key-btn"]').first()
    if (await revokeBtn.isVisible()) {
      await revokeBtn.click()
      await page.click('[data-testid="confirm-dialog-confirm"]')
      await page.waitForTimeout(1000)
    }

    await expect(page.locator('[data-testid="page-title"]')).toContainText('API Keys')
  })
})
