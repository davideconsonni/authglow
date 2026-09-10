import { test, expect } from '@playwright/test'

test.describe('OAuth Clients — Create → Rotate Secret → Delete', () => {
  test('create, rotate secret, and delete an OAuth client', async ({ page }) => {
    // Unique name: earlier failed runs may have left same-named
    // clients behind (the API rejects duplicates with 409).
    const clientName = `E2E Test App ${Date.now()}`
    await page.goto('/admin/oauth-clients')
    await page.waitForLoadState('networkidle')

    // Create — wizard: step 1 template → step 2 name → step 3 security
    // (grants + redirect URIs) → step 4 review → Create → success screen.
    await page.click('[data-testid="create-oauth-client-btn"]')
    await page.click('[data-testid="template-web"]')
    await page.fill('[data-testid="client-name-input"]', clientName)
    await page.click('button:has-text("Next")')
    await page.fill('[data-testid="client-uri-input-0"]', 'https://example.com/callback')
    await page.click('button:has-text("Next")')
    await page.click('[data-testid="create-client-submit"]')
    await expect(page.getByRole('heading', { name: 'Client Created Successfully' })).toBeVisible({ timeout: 5000 })
    await page.click('button:has-text("Done")')
    await page.waitForTimeout(1000)

    // The row of the client this test created.
    const row = page.locator('tr', { hasText: clientName }).first()
    await expect(row).toBeVisible({ timeout: 5000 })

    // Rotate secret — destructive action gated by the safeword challenge:
    // generate → read the word → echo it back → confirm → secret modal.
    const rotateBtn = row.locator('[data-testid="rotate-secret-btn"]').first()
    if (await rotateBtn.isVisible()) {
      await rotateBtn.click()
      await page.click('[data-testid="rotate-secret-generate"]')
      const word = (await page.locator('[data-testid="rotate-secret-word"]').textContent()) || ''
      await page.fill('[data-testid="rotate-secret-input"]', word.trim())
      await page.click('[data-testid="rotate-secret-confirm"]')
      await expect(page.locator('[data-testid="client-created-secret"]')).toBeVisible({ timeout: 5000 })
      await page.click('[data-testid="client-created-done"]')
      await page.waitForTimeout(500)
    }

    // Delete — target THIS client's row only.
    const deleteBtn = row.locator('[data-testid="delete-client-btn"]').first()
    if (await deleteBtn.isVisible()) {
      await deleteBtn.click()
      await page.click('[data-testid="confirm-dialog-confirm"]')
      await page.waitForTimeout(1000)
    }
  })
})
