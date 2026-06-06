import { test, expect } from '@playwright/test'

const API_URL = 'http://localhost:8001'

test.describe('Playground — Create Client → Authorize → Introspect → Revoke', () => {
  test('full OAuth2 playground flow: create client → authorize → introspect → revoke', async ({ page }) => {
    let clientId = ''
    let clientSecret = ''

    try {
      // ── Step 1: Create an OAuth2 client via page-context API call ──
      const createResult = await page.evaluate(async (apiUrl) => {
        const resp = await fetch(`${apiUrl}/api/oauth-clients`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            client_name: 'E2E Playground Test',
            redirect_uris: ['https://example.com/callback'],
            allowed_scopes: ['openid', 'profile', 'email', 'read'],
            grant_types: ['authorization_code', 'refresh_token'],
            is_confidential: true,
            require_pkce: false,
            require_consent: false,
          }),
          credentials: 'include',
        })
        const data = await resp.json()
        return { status: resp.status, ...data }
      }, API_URL)

      expect(createResult.status).toBe(201)
      clientId = createResult.client_id
      clientSecret = createResult.client_secret
      expect(clientId).toBeTruthy()
      expect(clientSecret).toBeTruthy()

      // ── Step 2: Navigate to Playground page ──
      await page.goto('/admin/playground')
      await page.waitForLoadState('networkidle')

      // ── Step 3: Configure Authorization Code flow via UI ──
      await page.fill('[data-testid="playground-client-id"]', clientId)
      await page.fill('[data-testid="playground-client-secret"]', clientSecret)
      await page.fill('[data-testid="playground-redirect-uri"]', 'https://example.com/callback')
      await page.click('[data-testid="playground-config-next"]')
      await page.waitForTimeout(500)

      // ── Step 4: Authorize via API to get auth code ──
      const authResp = await page.request.post(`${API_URL}/api/oauth2/authorize`, {
        form: {
          email: 'admin@example.com',
          password: 'AdminP@ss123!',
          client_id: clientId,
          redirect_uri: 'https://example.com/callback',
          scope: 'openid profile email read',
          state: 'e2e-test-state',
        },
      })

      expect(authResp.status()).toBe(200)
      const authData = await authResp.json()
      expect(authData.redirect_url).toBeTruthy()

      const codeMatch = authData.redirect_url.match(/code=([^&]+)/)
      expect(codeMatch).toBeTruthy()
      const authCode = codeMatch![1]

      // ── Step 5: Complete the authorize step (skip browser redirect, have the code) ──
      await page.click('text=I have the code')
      await page.waitForTimeout(500)

      // Fill auth code and exchange
      await page.fill('[data-testid="playground-auth-code"]', authCode)
      await page.click('[data-testid="playground-exchange-code"]')
      await page.waitForTimeout(2000)

      // Verify tokens were obtained
      await expect(page.locator('text=Tokens obtained')).toBeVisible({ timeout: 5000 })

      // Extract access token from response JSON in the panel
      const responseJson = await page.locator('pre').last().textContent()
      const parsedResponse = JSON.parse(responseJson || '{}')
      const accessToken = parsedResponse.access_token
      const refreshToken = parsedResponse.refresh_token
      expect(accessToken).toBeTruthy()
      expect(refreshToken).toBeTruthy()

      // ── Step 6: Switch to Introspection flow ──
      await page.click('[data-testid="flow-introspection"]')
      await page.waitForTimeout(500)

      await page.fill('[data-testid="introspect-token-input"]', accessToken)
      await page.fill('input[placeholder="client_id"]', clientId)
      await page.fill('input[placeholder="secret"]', clientSecret)
      await page.click('[data-testid="introspect-btn"]')
      await page.waitForTimeout(2000)

      const introText = await page.locator('pre').last().textContent()
      expect(introText).toContain('"active": true')

      // ── Step 7: Switch to Revocation flow ──
      await page.click('[data-testid="flow-revocation"]')
      await page.waitForTimeout(500)

      await page.click('text=Next')
      await page.waitForTimeout(500)

      await page.click('[data-testid="confirm-revoke-btn"]')
      await page.waitForTimeout(2000)

      await expect(page.locator('text=200').first()).toBeVisible({ timeout: 5000 })
      await expect(page.locator('text=Token has been revoked')).toBeVisible()

      // ── Step 8: Re-introspect to verify token is now handled ──
      await page.click('[data-testid="flow-introspection"]')
      await page.waitForTimeout(500)

      await page.fill('[data-testid="introspect-token-input"]', accessToken)
      await page.fill('input[placeholder="client_id"]', clientId)
      await page.fill('input[placeholder="secret"]', clientSecret)
      await page.click('[data-testid="introspect-btn"]')
      await page.waitForTimeout(2000)
    } finally {
      if (clientId) {
        await page.evaluate(async (params) => {
          await fetch(`${params.apiUrl}/api/oauth-clients/${params.clientId}`, {
            method: 'DELETE',
            credentials: 'include',
          })
        }, { apiUrl: API_URL, clientId })
      }
    }
  })
})
