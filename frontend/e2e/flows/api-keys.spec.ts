import { test, expect } from '@playwright/test'

test.describe('API Keys — Create → Copy → Revoke', () => {
  test('create and revoke an API key', async ({ page }) => {
    await page.goto('/api-keys')
    await page.waitForLoadState('networkidle')

    await page.click('[data-testid="create-api-key-btn"]')
    await expect(page.locator('[data-testid="create-key-modal"]')).toBeVisible()

    await page.fill('[data-testid="key-name-input"]', 'E2E Test Key')
    await page.fill('[data-testid="key-description-input"]', 'Created during E2E for context tracking')
    // ScopePicker: scope chips + custom-scope input (Enter adds the token).
    await page.fill('[data-testid="key-scopes-custom-input"]', 'read')
    await page.keyboard.press('Enter')
    await page.click('[data-testid="key-create-submit"]')

    await expect(page.locator('[data-testid="key-created-display"]')).toBeVisible({ timeout: 5000 })
    const keyText = await page.locator('[data-testid="key-created-display"] code').textContent()
    expect(keyText).toBeTruthy()

    const warning = page.locator('[data-testid="scope-filter-warning"]')
    if (await warning.isVisible()) {
      await expect(warning).toContainText('Requested')
      await expect(warning).toContainText('Granted')
      await expect(warning).toContainText('Filtered')
    }

    await page.click('[data-testid="key-created-done"]')

    // Key description renders in both the desktop table and the mobile
    // cards (the table rows are hidden on small viewports) — always
    // target the visible variant.
    const descDisplay = page.locator('[data-testid="key-description-display"]:visible').first()
    await expect(descDisplay).toContainText('Created during E2E for context tracking', { timeout: 8000 })

    const editBtn = page.locator('[data-testid="key-edit-btn"]:visible').first()
    await editBtn.click()
    await expect(page.locator('[data-testid="key-edit-modal"]')).toBeVisible()
    await page.fill(
      '[data-testid="key-edit-description-input"]',
      'Updated by E2E test',
    )
    await page.click('[data-testid="key-edit-submit"]')
    await expect(descDisplay).toContainText('Updated by E2E test', { timeout: 5000 })

    const revokeBtn = page.locator('[data-testid="revoke-key-btn"]:visible').first()
    if (await revokeBtn.isVisible()) {
      await revokeBtn.click()
      await page.click('[data-testid="confirm-dialog-confirm"]')
      await page.waitForTimeout(1000)
    }

    await expect(page.locator('[data-testid="page-title"]')).toContainText('API Keys')
  })
})
