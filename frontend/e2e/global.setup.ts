import { chromium, type FullConfig } from '@playwright/test'
import { loginViaUI } from './auth.setup'

const BASE_URL = 'http://localhost:5173'

async function globalSetup(_config: FullConfig) {
  const browser = await chromium.launch()
  const page = await browser.newPage()

  await page.goto(`${BASE_URL}/auth/login`)
  await page.waitForLoadState('networkidle')
  await page.evaluate(() => localStorage.removeItem('auth-storage'))
  await page.reload()
  await page.waitForLoadState('networkidle')

  // loginViaUI resolves the demo password from GET /api/meta in demo mode.
  await loginViaUI(page)

  await page.context().storageState({ path: 'e2e/.auth/state.json' })
  await browser.close()
}

export default globalSetup
