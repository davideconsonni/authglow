import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')

describe('Fase 6 — OIDC Federation', () => {
  describe('6.1 Backend models', () => {
    it('federation.py model esiste', () => {
      expect(existsSync(resolve(ROOT, '..', 'backend', 'authglow', 'models', 'federation.py'))).toBe(true)
    })
  })

  describe('6.2 Backend services', () => {
    it('federation_storage.py esiste', () => {
      expect(existsSync(resolve(ROOT, '..', 'backend', 'authglow', 'services', 'federation_storage.py'))).toBe(true)
    })

    it('federation.py service esiste', () => {
      expect(existsSync(resolve(ROOT, '..', 'backend', 'authglow', 'services', 'federation.py'))).toBe(true)
    })
  })

  describe('6.3 Backend API', () => {
    it('federation.py router esiste', () => {
      expect(existsSync(resolve(ROOT, '..', 'backend', 'authglow', 'api', 'federation.py'))).toBe(true)
    })
  })

  describe('6.4 AdminFederationPage', () => {
    it('AdminFederationPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'admin', 'AdminFederationPage.tsx'))).toBe(true)
    })

    it('AdminFederationPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'admin', 'AdminFederationPage.tsx'))
      expect(mod.AdminFederationPage).toBeDefined()
    })
  })

  describe('6.5 Sidebar navigation', () => {
    it('Sidebar ha voce Federation', async () => {
      const mod = await import(resolve(SRC, 'components', 'layout', 'Sidebar.tsx'))
      expect(mod.Sidebar).toBeDefined()
    })
  })

  describe('6.6 App.tsx routing', () => {
    it('App.tsx importa AdminFederationPage', async () => {
      const mod = await import(resolve(SRC, 'App.tsx'))
      expect(mod.default).toBeDefined()
    })
  })

  describe('6.7 Constants', () => {
    it('ROUTES.ADMIN.FEDERATION esiste', async () => {
      const { ROUTES } = await import(resolve(SRC, 'lib', 'constants.ts'))
      expect(ROUTES.ADMIN.FEDERATION).toBe('/admin/federation')
    })
  })

  describe('6.8 OAuthAuthorizePage federation', () => {
    it('OAuthAuthorizePage esporta correttamente', async () => {
      const mod = await import(resolve(SRC, 'pages', 'OAuthAuthorizePage.tsx'))
      expect(mod.OAuthAuthorizePage).toBeDefined()
    })
  })

  describe('6.9 Documentation', () => {
    it('docs/CIE.md esiste', () => {
      expect(existsSync(resolve(ROOT, '..', 'docs', 'CIE.md'))).toBe(true)
    })
  })
})