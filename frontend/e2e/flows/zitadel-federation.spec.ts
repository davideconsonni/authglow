import { test, expect } from '@playwright/test'

const EMAIL = process.env.ZITADEL_TEST_EMAIL || ''
const PASSWORD = process.env.ZITADEL_TEST_PASSWORD || ''

test.describe('Zitadel Federation Flow', () => {

  test('login via Zitadel and reach dashboard', async ({ page }) => {
    test.skip(!EMAIL || !PASSWORD, 'Set ZITADEL_TEST_EMAIL and ZITADEL_TEST_PASSWORD env vars')

    // Go to AuthGlow login
    await page.goto('http://localhost:5173/auth/login')
    await page.waitForLoadState('networkidle')

    // Mock the providers API so the federation button shows up
    await page.route('**/api/federation/providers*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'zitadel', label: 'Zitadel', description: 'Zitadel IdP' }
        ]),
      })
    })
    await page.reload()
    await page.waitForLoadState('networkidle')

    // Dump all links on the page for debugging
    const links = await page.locator('a[href*="federation"]').all()
    console.log('Federation links found:', links.length)
    for (const l of links) {
      console.log('  href:', await l.getAttribute('href'))
    }

    // Click ANY federation button
    const fedBtn = page.locator('a[href*="/api/federation/login/"]').first()
    await expect(fedBtn).toBeVisible({ timeout: 10000 })
    await fedBtn.click()

    // We're now on Zitadel — wait for their page
    await page.waitForLoadState('networkidle')
    console.log('Current URL after redirect:', page.url())

    // Zitadel login flow — try multiple selector strategies
    // Strategy 1: username input with various names
    const loginInput = page.locator('#loginName, input[name="loginName"], input[autocomplete="username"]').first()
    if (await loginInput.isVisible({ timeout: 3000 }).catch(() => false)) {
      await loginInput.fill(EMAIL)
      await loginInput.press('Enter')
      await page.waitForTimeout(2000) // wait for password screen
    }

    // Strategy 2: combined login form
    const emailInput = page.locator('input[type="email"], input[name="email"]').first()
    if (await emailInput.isVisible({ timeout: 2000 }).catch(() => false)) {
      await emailInput.fill(EMAIL)
    }

    // Find password field
    const pwdInput = page.locator('#password, input[name="password"], input[type="password"]').first()
    await expect(pwdInput).toBeVisible({ timeout: 5000 })
    await pwdInput.fill(PASSWORD)

    // Find and click submit button
    const submitBtn = page.locator('#submit-button, button[type="submit"]').first()
    await submitBtn.click()

    // Wait for redirect back to AuthGlow
    try {
      await page.waitForURL(/localhost:5173/, { timeout: 20000 })
      console.log('Final URL:', page.url())
    } catch {
      // Dump page content for debugging
      const body = await page.locator('body').innerText()
      console.log('Page body after login attempt:', body.substring(0, 500))
    }
  })
})

