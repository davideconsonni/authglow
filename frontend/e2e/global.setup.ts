import { chromium, type FullConfig } from '@playwright/test'

const BASE_URL = 'http://localhost:5173'

async function globalSetup(_config: FullConfig) {
  const browser = await chromium.launch()
  const page = await browser.newPage()

  await page.goto(`${BASE_URL}/auth/login`)
  await page.waitForLoadState('networkidle')

  await page.fill('[data-testid="login-email"]', 'admin@example.com')
  await page.fill('[data-testid="login-password"]', 'AdminP@ss123!')
  await page.click('[data-testid="login-submit"]')
  await page.waitForURL('**/dashboard')
  await page.waitForLoadState('networkidle')

  await page.context().storageState({ path: 'e2e/.auth/state.json' })
  await browser.close()
}

export default globalSetup
