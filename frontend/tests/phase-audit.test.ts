import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')

describe('Fase Audit Endpoints — Cover Frontend', () => {
  describe('SessionsPage (utente)', () => {
    it('usa /api/tokens/refresh/list invece di /api/admin/sessions', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'SessionsPage.tsx'), 'utf-8')
      expect(source).toContain('/api/tokens/refresh/list')
      expect(source).not.toContain('/api/admin/sessions')
    })

    it('usa /api/tokens/refresh/revoke-all invece di /api/admin/sessions/cleanup', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'SessionsPage.tsx'), 'utf-8')
      expect(source).toContain('/api/tokens/refresh/revoke-all')
    })

    it('usa ConfirmDialog per singola revoca con conferma', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'SessionsPage.tsx'), 'utf-8')
      expect(source).toContain('ConfirmDialog')
    })
  })

  describe('AdminOAuthClientsPage — Edit', () => {
    it('contiene handleUpdate', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain('handleUpdate')
    })

    it('contiene openEdit', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain('openEdit')
    })

    it('contiene editClientId state', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain('editClientId')
    })

    it('chiama PUT /api/oauth-clients/{id} per update', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain("api.put(`/api/oauth-clients/${editClientId}`")
    })

    it('ha bottone Edit nella tabella', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain('Edit')
    })

    it('modal mostra Edit OAuth Client in edit mode', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain("'Edit OAuth Client'")
    })

    it('pulsante submit dice Update in edit mode', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).toContain("'Update'")
    })

    it('modal in edit mode NON rende null (regression bug fix)', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')
      expect(source).not.toMatch(/editClientId \? null : !clientType/)
    })
  })

  describe('AdminOAuthClientsPage — Redesign (Quick start + full form)', () => {
    const source = () => readFileSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'), 'utf-8')

    it('esiste e ha il redesign con TEMPLATES', () => {
      expect(existsSync(resolve(SRC, 'pages', 'admin', 'AdminOAuthClientsPage.tsx'))).toBe(true)
      const s = source()
      expect(s).toContain('TEMPLATES')
      expect(s).toContain('applyTemplate')
    })

    it('espone 3 quick start template (web, service, mobile)', () => {
      const s = source()
      expect(s).toContain("id: 'web'")
      expect(s).toContain("id: 'service'")
      expect(s).toContain("id: 'mobile'")
      expect(s).toContain('data-testid={`template-${t.id}`}')
    })

    it('Service template ha client_credentials + refresh_token (no redirect_uris)', () => {
      const s = source()
      const serviceMatch = s.match(/id: 'service'[\s\S]*?show_redirect_uris: (\w+)/)
      expect(serviceMatch).toBeTruthy()
      expect(serviceMatch![1]).toBe('false')
      expect(s).toMatch(/id: 'service'[\s\S]*?grant_types: \['client_credentials', 'refresh_token'\]/)
    })

    it('Mobile template ha authorization_code + public + PKCE required', () => {
      const s = source()
      expect(s).toMatch(/id: 'mobile'[\s\S]*?grant_types: \['authorization_code', 'refresh_token'\]/)
      expect(s).toMatch(/id: 'mobile'[\s\S]*?is_confidential: false/)
      expect(s).toMatch(/id: 'mobile'[\s\S]*?require_pkce: true/)
    })

    it('redirect_uris è mostrato SOLO se authorization_code è checked', () => {
      const s = source()
      expect(s).toContain('showRedirectUris')
      expect(s).toContain('grantTypes.includes(\'authorization_code\')')
    })

    it('PKCE è locked a true per public client', () => {
      const s = source()
      expect(s).toMatch(/isConfidential \? requirePkce : true/)
      expect(s).toMatch(/disabled=\{!isConfidential\}/)
    })

    it('auth_method è disabilitato per public client', () => {
      const s = source()
      expect(s).toMatch(/disabled=\{!isConfidential\}/)
    })

    it('breaking change warning mostrato in edit se cambiano grant_types o is_confidential', () => {
      const s = source()
      expect(s).toContain('showBreakingChangeWarning')
      expect(s).toContain('data-testid="breaking-change-warning"')
      expect(s).toContain('originalGrantTypes')
      expect(s).toContain('originalIsConfidential')
    })

    it('validazione: almeno un grant_type richiesto', () => {
      const s = source()
      expect(s).toMatch(/grantTypes\.length === 0.*Select at least one grant type/)
    })

    it('validazione: redirect_uris richiesti SOLO con authorization_code', () => {
      const s = source()
      expect(s).toMatch(/grantTypes\.includes\(.authorization_code.\)[\s\S]*?redirect_uris.*required/)
    })

    it('invia allowed_scopes (NON scopes) al backend', () => {
      const s = source()
      expect(s).toContain('allowed_scopes:')
      expect(s).not.toMatch(/scopes:\s*scopesList/)
    })

    it('invia is_confidential in create e update', () => {
      const s = source()
      expect(s).toContain('is_confidential: isConfidential')
    })

    it('invia token_endpoint_auth_method', () => {
      const s = source()
      expect(s).toContain('token_endpoint_auth_method: authMethod')
    })

    it('invia dpop_bound (T.3 DPoP / RFC 9449)', () => {
      const s = source()
      expect(s).toContain('dpop_bound: dpopBound')
    })

    it('ha il toggle DPoP-bound nella UI', () => {
      const s = source()
      // T.3: il toggle deve avere data-testid per testing E2E
      expect(s).toContain('data-testid="dpop-bound-toggle"')
    })

    it('invia description, homepage_uri, logo_uri, terms_uri, privacy_uri', () => {
      const s = source()
      expect(s).toContain('description:')
      expect(s).toContain('homepage_uri:')
      expect(s).toContain('logo_uri:')
      expect(s).toContain('terms_uri:')
      expect(s).toContain('privacy_uri:')
    })

    it('invia access_token_lifetime e refresh_token_lifetime', () => {
      const s = source()
      expect(s).toContain('access_token_lifetime:')
      expect(s).toContain('refresh_token_lifetime:')
    })

    it('campo description presente nel form', () => {
      const s = source()
      expect(s).toContain('setDescription(')
    })

    it('campo access_token_lifetime ha hint sui bounds (300-86400)', () => {
      const s = source()
      expect(s).toMatch(/300.*86400/)
    })
  })

  describe('PasskeyLoginButton', () => {
    it('PasskeyLoginButton.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'))).toBe(true)
    })

    it('PasskeyLoginButton è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'))
      expect(mod.PasskeyLoginButton).toBeDefined()
    })

    it('chiama /api/passkey/auth/begin', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'), 'utf-8')
      expect(source).toContain('/api/passkey/auth/begin')
    })

    it('chiama /api/passkey/auth/complete', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'), 'utf-8')
      expect(source).toContain('/api/passkey/auth/complete')
    })

    it('usa startAuthentication da @simplewebauthn/browser', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'), 'utf-8')
      expect(source).toContain('startAuthentication')
    })

    it('invia campi separati per auth complete (non oggetto intero)', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'auth', 'PasskeyLoginButton.tsx'), 'utf-8')
      expect(source).toContain('credential_id: authResult.id')
      expect(source).toContain('client_data_json: authResult.response.clientDataJSON')
      expect(source).toContain('authenticator_data: authResult.response.authenticatorData')
      expect(source).toContain('signature: authResult.response.signature')
    })
  })

  describe('LoginPage — include PasskeyLoginButton', () => {
    it('LoginPage importa PasskeyLoginButton', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'auth', 'LoginPage.tsx'), 'utf-8')
      expect(source).toContain('PasskeyLoginButton')
    })
  })

  describe('PasskeyManager — registration campi separati', () => {
    it('PasskeyManager.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'profile', 'PasskeyManager.tsx'))).toBe(true)
    })

    it('invia campi separati per register complete (non oggetto intero)', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'profile', 'PasskeyManager.tsx'), 'utf-8')
      expect(source).toContain('credential_id: regResult.id')
      expect(source).toContain('client_data_json: regResult.response.clientDataJSON')
      expect(source).toContain('attestation_object: regResult.response.attestationObject')
    })

    it('usa credential_id (NON id) per matchare il backend PasskeyResponse', () => {
      const source = readFileSync(resolve(SRC, 'components', 'profile', 'PasskeyManager.tsx'), 'utf-8')
      expect(source).toContain('credential_id: string')
      expect(source).toContain('key={pk.credential_id}')
      expect(source).toContain('setDeleteId(pk.credential_id)')
      expect(source).not.toMatch(/key=\{pk\.id\}/)
    })
  })

  describe('ResendVerificationBanner', () => {
    it('ResendVerificationBanner.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'auth', 'ResendVerificationBanner.tsx'))).toBe(true)
    })

    it('ResendVerificationBanner è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'auth', 'ResendVerificationBanner.tsx'))
      expect(mod.ResendVerificationBanner).toBeDefined()
    })

    it('chiama /api/email/resend-verification', async () => {
      const source = readFileSync(resolve(SRC, 'components', 'auth', 'ResendVerificationBanner.tsx'), 'utf-8')
      expect(source).toContain('/api/email/resend-verification')
    })
  })

  describe('AdminPasswordResetsPage — fix delete + email', () => {
    it('chiama DELETE con token id', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminPasswordResetsPage.tsx'), 'utf-8')
      expect(source).toContain('/api/admin/password-resets/')
    })
  })

  describe('CONFORMANCE T.4 — docs/FAPI.md', () => {
    const fapiPath = resolve(ROOT, '..', 'docs', 'FAPI.md')

    it('docs/FAPI.md esiste', () => {
      expect(existsSync(fapiPath)).toBe(true)
    })

    it('docs/FAPI.md contiene il gap analysis principale', () => {
      const content = readFileSync(fapiPath, 'utf-8')
      // Le sezioni obbligatorie devono essere presenti.
      expect(content).toContain('Conformance Matrix')
      expect(content).toContain('Gap Roadmap')
      expect(content).toContain('PAR')
      expect(content).toContain('DPoP')
      expect(content).toContain('mTLS')
    })

    it('docs/FAPI.md documenta T.2 (client_secret_jwt / private_key_jwt)', () => {
      const content = readFileSync(fapiPath, 'utf-8')
      expect(content).toContain('client_secret_jwt')
      expect(content).toContain('private_key_jwt')
    })

    it('docs/FAPI.md documenta T.3 (DPoP RFC 9449)', () => {
      const content = readFileSync(fapiPath, 'utf-8')
      expect(content).toContain('RFC 9449')
      expect(content).toContain('ES256')
      expect(content).toContain('cnf')
    })
  })
})
