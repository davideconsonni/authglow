import { test, expect } from '@playwright/test'
import { clearAuth } from '../auth.setup'

test.describe('Federation + OAuth2 consent flow', () => {
  test('OAuth authorize page shows federation buttons when providers exist', async ({ page }) => {
    await page.route('**/api/oauth2/authorize-info*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          client_name: 'Test OAuth App',
          client_description: 'A test OAuth2 client',
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
        }),
      })
    })

    await page.route('**/api/federation/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          {
            id: 'google',
            label: 'Google',
            description: 'Sign in with your Google account',
            icon_uri: null,
            logo_uri: null,
          },
          {
            id: 'cie',
            label: 'CIE',
            description: 'Carta d\'Identità Elettronica',
            icon_uri: null,
            logo_uri: null,
          },
        ]),
      })
    })

    await page.goto('/oauth2/authorize?client_id=test-client&redirect_uri=https://example.com/cb&scope=openid+email')

    await page.waitForSelector('[data-testid="fed-provider-google"]', { timeout: 5000 })
    await expect(page.getByTestId('fed-provider-google')).toBeVisible()
    await expect(page.getByTestId('fed-provider-cie')).toBeVisible()

    const googleLink = page.getByTestId('fed-provider-google')
    const href = await googleLink.getAttribute('href')
    expect(href).toContain('/api/federation/login/google')
    expect(href).toContain('client_id=test-client')
    expect(href).toContain('oauth_redirect_uri=https%3A%2F%2Fexample.com%2Fcb')
  })

  test('OAuth authorize page shows consent after federated session', async ({ page }) => {
    const mockSessionToken = 'mock-session-token-12345'

    await page.route('**/api/oauth2/authorize-info*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          client_name: 'Federated App',
          client_description: 'OAuth2 client for federated users',
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
        }),
      })
    })

    await page.route('**/api/oauth2/federated-consent', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          consent_required: true,
          session_token: mockSessionToken,
          client_name: 'Federated App',
          client_description: 'OAuth2 client for federated users',
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
          scopes: [
            { name: 'openid', description: 'Verify your identity' },
            { name: 'email', description: 'Access your email address' },
          ],
        }),
      })
    })

    await page.goto('/oauth2/authorize?client_id=test-client&redirect_uri=https://example.com/cb&scope=openid+email')

    await expect(page.getByText('Federated App', { exact: true })).toBeVisible({ timeout: 5000 })
    await expect(page.getByText('Verify your identity')).toBeVisible()
    await expect(page.getByText('Access your email address')).toBeVisible()
  })

  test('consent screen denies access correctly', async ({ page }) => {
    const mockSessionToken = 'mock-session-token-deny'

    await page.route('**/api/oauth2/authorize-info*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          client_name: 'Deny Test App',
          client_description: null,
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
        }),
      })
    })

    await page.route('**/api/oauth2/federated-consent', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          consent_required: true,
          session_token: mockSessionToken,
          client_name: 'Deny Test App',
          client_description: null,
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
          scopes: [
            { name: 'openid', description: 'Verify your identity' },
          ],
        }),
      })
    })

    await page.route('**/oauth2/consent', async (route) => {
      const request = route.request()
      const postData = request.postData() || ''
      if (postData.includes('action=deny')) {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ denied: true }),
        })
      } else {
        await route.fulfill({
          status: 200,
          contentType: 'application/json',
          body: JSON.stringify({ approved: true }),
        })
      }
    })

    await page.goto('/oauth2/authorize?client_id=test-client&redirect_uri=https://example.com/cb')

    await expect(page.getByText('Deny Test App', { exact: true })).toBeVisible({ timeout: 5000 })
    await expect(page.getByRole('button', { name: /Deny/i })).toBeVisible()
  })

  test('federation login link includes all OAuth2 params on authorize page', async ({ page }) => {
    await page.route('**/api/oauth2/authorize-info*', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          client_name: 'PKCE Test App',
          client_description: null,
          client_logo_uri: null,
          client_homepage_uri: null,
          client_terms_uri: null,
          client_privacy_uri: null,
          custom_css: null,
        }),
      })
    })

    await page.route('**/api/federation/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'google', label: 'Google', description: null, icon_uri: null, logo_uri: null },
        ]),
      })
    })

    const testParams = new URLSearchParams({
      client_id: 'pkce-client',
      redirect_uri: 'https://pkce.example.com/cb',
      scope: 'openid profile email',
      state: 'app-state-xyz',
      code_challenge: 'base64url-challenge',
      code_challenge_method: 'S256',
      response_type: 'code',
      nonce: 'nonce-abc-123',
    })

    await page.goto(`/oauth2/authorize?${testParams.toString()}`)

    await page.waitForSelector('[data-testid="fed-provider-google"]', { timeout: 5000 })

    const googleLink = page.getByTestId('fed-provider-google')
    const href = await googleLink.getAttribute('href')

    expect(href).toContain('client_id=pkce-client')
    expect(href).toContain('scope=openid+profile+email')
    expect(href).toContain('app_state=app-state-xyz')
    expect(href).toContain('code_challenge=base64url-challenge')
    expect(href).toContain('code_challenge_method=S256')
    expect(href).toContain('response_type=code')
    expect(href).toContain('oidc_nonce=nonce-abc-123')
  })

  test('federation login link without OAuth2 params works for direct login', async ({ page }) => {
    await page.route('**/api/federation/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'google', label: 'Google', description: null, icon_uri: null, logo_uri: null },
        ]),
      })
    })

    await clearAuth(page)
    await page.route('**/api/federation/providers', async (route) => {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify([
          { id: 'google', label: 'Google', description: null, icon_uri: null, logo_uri: null },
        ]),
      })
    })
    await page.goto('/auth/login', { waitUntil: 'networkidle' })
    await page.waitForSelector('[data-testid="fed-provider-google"]', { timeout: 5000 })

    const googleLink = page.getByTestId('fed-provider-google')
    const href = await googleLink.getAttribute('href')

    expect(href).toContain('/api/federation/login/google')
    expect(href).toContain('redirect_uri=')
    expect(href).not.toContain('client_id=')
    expect(href).not.toContain('oauth_redirect_uri=')
  })
})
