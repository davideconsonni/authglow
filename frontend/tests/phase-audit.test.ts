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

    it('non importa piu ConfirmDialog (remove per singola revoca)', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'SessionsPage.tsx'), 'utf-8')
      expect(source).not.toContain('ConfirmDialog')
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
})
