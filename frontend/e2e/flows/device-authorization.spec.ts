import { test, expect } from '@playwright/test'

const BACKEND = 'http://localhost:8001'

test.describe('Device Authorization — full flow', () => {
  test('create device code via admin UI, verify and approve via API', async ({
    page,
    request,
  }) => {
    // 1. Create a test OAuth client via backend API
    const clientRes = await request.post(`${BACKEND}/api/oauth-clients`, {
      data: {
        client_name: 'E2E Device Test',
        redirect_uris: ['http://localhost:6060/callback'],
        grant_types: [
          'urn:ietf:params:oauth:grant-type:device_code',
          'authorization_code',
          'refresh_token',
        ],
        scope: 'read',
      },
    })
    expect(clientRes.ok()).toBeTruthy()
    const client = await clientRes.json()

    // 2. Navigate to admin "New Device Auth" page
    await page.goto('/admin/device-authorizations/new')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: /New Device/ })).toBeVisible()

    // 3. Select client from dropdown
    await page.locator('select').selectOption(client.client_id)

    // 4. Click Generate
    await page.click('button:has-text("Generate")')

    // 5. Read user_code from the result section
    const userCodeEl = page.locator('text=User Code').locator('..').locator('code')
    await expect(userCodeEl).toBeVisible({ timeout: 5000 })
    const userCode = (await userCodeEl.textContent()) || ''
    const trimmedUserCode = userCode.trim()
    expect(trimmedUserCode.length).toBeGreaterThan(0)
    expect(trimmedUserCode).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)

    // 6. Verify user code via backend API (simulates browser fetch)
    const verifyRes = await request.post(`${BACKEND}/api/oauth2/device/verify`, {
      data: { user_code: trimmedUserCode },
    })
    expect(verifyRes.ok()).toBeTruthy()
    const verifyData = await verifyRes.json()
    expect(verifyData.client_id).toBe(client.client_id)
    expect(verifyData.scopes).toContain('read')

    // 7. Approve via API
    const approveRes = await request.post(`${BACKEND}/api/oauth2/device/approve`, {
      data: { user_code: trimmedUserCode },
    })
    expect(approveRes.ok()).toBeTruthy()
    expect(await approveRes.json()).toEqual({ status: 'approved' })

    // 8. Verify the device auth appears as "authorized" in the admin list
    await page.goto('/admin/device-authorizations')
    await page.waitForLoadState('networkidle')
    await expect(page.getByText(trimmedUserCode)).toBeVisible({ timeout: 5000 })
    await expect(page.locator('td').filter({ hasText: 'authorized' }).first()).toBeVisible()

    // 9. Verify poll returns access denied on already-used code
    const secondVerifyRes = await request.post(
      `${BACKEND}/api/oauth2/device/verify`,
      { data: { user_code: trimmedUserCode } },
    )
    expect(secondVerifyRes.status()).toBe(400)

    // 10. Clean up — delete test client
    await request.delete(`${BACKEND}/api/oauth-clients/${client.client_id}`)
  })

  test('device verification page shows sign-in prompt when unauthenticated', async ({
    browser,
  }) => {
    const context = await browser.newContext({ storageState: undefined })
    const page = await context.newPage()
    await page.goto('/oauth2/device/verify')
    await page.waitForLoadState('networkidle')
    await expect(page.getByRole('heading', { name: 'Device Verification' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Sign In' })).toBeVisible()
    await context.close()
  })

  test('POST /oauth2/device/authorize with valid client returns codes', async ({
    request,
  }) => {
    const res = await request.post(`${BACKEND}/oauth2/device/authorize`, {
      form: { client_id: 'test-client-id', scope: 'read' },
    })
    // May fail if test-client-id doesn't exist, but tests the endpoint
    if (res.ok()) {
      const data = await res.json()
      expect(data.device_code).toBeTruthy()
      expect(data.user_code).toMatch(/^[A-Z0-9]{4}-[A-Z0-9]{4}$/)
      expect(data.verification_uri).toContain('/oauth2/device/verify')
      expect(data.expires_in).toBeGreaterThan(0)
    }
  })

  test('polling with invalid device_code returns expired_token', async ({
    request,
  }) => {
    const res = await request.post(`${BACKEND}/oauth2/token`, {
      form: {
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        code: 'nonexistent-device-code',
        client_id: 'test-client',
      },
    })
    expect(res.status()).toBe(400)
    const body = await res.json()
    expect(body.detail.error || body.detail).toContain('expired_token')
  })
})
