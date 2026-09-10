import { test, expect } from '@playwright/test'
import { csrfHeaders, getCsrfToken, getDemoPassword } from '../auth.setup'

const API_URL = 'http://localhost:8001'

test.describe('Playground — Create Client → Authorize → Introspect → Revoke', () => {
  test('full OAuth2 playground flow: create client → authorize → introspect → revoke', async ({
    page,
    request,
  }) => {
    // The flow has ~8s of fixed waits plus a multi-hop OAuth dance —
    // the throttled mobile device needs headroom beyond the 30s default.
    test.setTimeout(90000)
    const { randomBytes, createHash } = await import('node:crypto')
    const b64url = (buf: Buffer) =>
      buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    const E2E_SCOPES = 'openid profile email read offline_access'
    // Node-side PKCE pair: the UI keeps its own verifier in React state
    // (unreachable from here), so authorize+exchange go through the API
    // with this pair; introspect/revoke run in the playground UI.
    const verifier = b64url(randomBytes(32))
    const challenge = b64url(createHash('sha256').update(verifier).digest())
    const nonce = b64url(randomBytes(16))
    const state = `e2e-test-state-${Date.now()}`
    let clientId: string
    let clientSecret: string
    let csrfTokenValue = ''
    const demoPassword = await getDemoPassword()

    try {
      // Cookie-authenticated unsafe calls need the CSRF token header; the
      // `request` fixture shares the browser context's cookies.
      csrfTokenValue = await getCsrfToken(request)
      // ── Step 1: Create an OAuth2 client via the API (request fixture
      // shares the logged-in session's cookies). Unique name — earlier
      // failed runs may have left same-named clients behind (409). ──
      const createRes = await request.post(`${API_URL}/api/oauth-clients`, {
        headers: csrfHeaders(csrfTokenValue),
        data: {
          client_name: `E2E Playground Test ${Date.now()}`,
          redirect_uris: ['https://example.com/callback'],
          allowed_scopes: ['openid', 'profile', 'email', 'read', 'offline_access'],
          grant_types: ['authorization_code', 'refresh_token'],
          is_confidential: true,
          require_pkce: false,
          require_consent: false,
        },
      })
      expect(createRes.status()).toBe(201)
      const created = await createRes.json()
      clientId = created.client_id
      clientSecret = created.client_secret
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
      // Fresh token: the step-2 page navigation rotated the one from step 1.
      const csrfStep4 = await (async () => {
        const res = await page.request.get(`${API_URL}/api/oauth2/csrf-token`)
        return ((await res.json()) as { csrf_token: string }).csrf_token
      })()
      const authResp = await page.request.post(`${API_URL}/api/oauth2/authorize`, {
        headers: { 'X-CSRF-Token': csrfStep4 },
        form: {
          email: 'admin@example.com',
          password: demoPassword,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: 'https://example.com/callback',
          response_type: 'code',
          scope: E2E_SCOPES,
          state,
          nonce,
          code_challenge: challenge,
          code_challenge_method: 'S256',
        },
      })

      expect(authResp.status()).toBe(200)
      const authData = await authResp.json()
      expect(authData.redirect_url).toBeTruthy()

      const codeMatch = authData.redirect_url.match(/code=([^&]+)/)
      expect(codeMatch).toBeTruthy()
      const authCode = codeMatch![1]

      // ── Step 5: Exchange the code via API (node PKCE pair) ──
      const csrfExchange = await getCsrfToken(request)
      const tokenRes = await request.post(`${API_URL}/oauth2/token`, {
        headers: csrfHeaders(csrfExchange),
        form: {
          grant_type: 'authorization_code',
          code: authCode,
          redirect_uri: 'https://example.com/callback',
          code_verifier: verifier,
          client_id: clientId,
          client_secret: clientSecret,
        },
      })
      expect(tokenRes.status()).toBe(200)
      const tokenData = await tokenRes.json()
      const accessToken = tokenData.access_token as string
      const refreshToken = tokenData.refresh_token as string
      expect(accessToken).toBeTruthy()
      expect(refreshToken).toBeTruthy()

      // ── Step 6: Switch to Introspection flow (input → Next → auth) ──
      // Desktop uses the flow sidebar buttons; mobile renders a <select>.
      if (await page.locator('[data-testid="flow-introspection"]').isVisible()) {
        await page.click('[data-testid="flow-introspection"]')
      } else {
        await page.locator('[data-testid="playground-flow-select"]').selectOption('introspection')
      }
      await page.waitForTimeout(500)

      await page.fill('[data-testid="introspect-token-input"]', accessToken)
      await page.click('button:has-text("Next")')
      await page.fill('input[placeholder="client_id"]', clientId)
      await page.fill('input[placeholder="secret"]', clientSecret)
      await page.click('[data-testid="introspect-btn"]')
      await page.waitForTimeout(2000)

      const introText = await page.locator('pre').last().textContent()
      expect(introText).toContain('"active": true')

      // ── Step 7: Switch to Revocation flow (input → Next → confirm) ──
      if (await page.locator('[data-testid="flow-revocation"]').isVisible()) {
        await page.click('[data-testid="flow-revocation"]')
      } else {
        await page.locator('[data-testid="playground-flow-select"]').selectOption('revocation')
      }
      await page.waitForTimeout(500)

      await page.fill('textarea[placeholder*="Paste the token"]', accessToken)
      await page.click('button:has-text("Next")')
      await page.waitForTimeout(500)

      await page.click('[data-testid="confirm-revoke-btn"]')
      await page.waitForTimeout(2000)

      await expect(page.locator('text=200').first()).toBeVisible({ timeout: 5000 })
      await expect(page.locator('text=Token has been revoked')).toBeVisible()

      // ── Step 8: Re-introspect to verify the token is now inactive ──
      if (await page.locator('[data-testid="flow-introspection"]').isVisible()) {
        await page.click('[data-testid="flow-introspection"]')
      } else {
        await page.locator('[data-testid="playground-flow-select"]').selectOption('introspection')
      }
      await page.waitForTimeout(500)

      await page.fill('[data-testid="introspect-token-input"]', accessToken)
      await page.click('button:has-text("Next")')
      await page.waitForTimeout(300)
      await page.fill('input[placeholder="client_id"]', clientId)
      await page.fill('input[placeholder="secret"]', clientSecret)
      await page.click('[data-testid="introspect-btn"]')
      await page.waitForTimeout(2000)

      const introText2 = await page.locator('pre').last().textContent()
      expect(introText2).toContain('"active": false')
    } finally {
      if (clientId) {
        // Fresh token: page navigations during the flow rotated it.
        const csrfFinal = await getCsrfToken(request).catch(() => csrfTokenValue)
        await request.delete(`${API_URL}/api/oauth-clients/${clientId}`, {
          headers: csrfHeaders(csrfFinal),
        })
      }
    }
  })
})
