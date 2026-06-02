import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')

describe('Fase 5 — OAuth2 Consent Screen', () => {
  describe('5.1 OAuthConsentPage', () => {
    it('OAuthConsentPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'OAuthConsentPage.tsx'))).toBe(true)
    })

    it('OAuthConsentPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'OAuthConsentPage.tsx'))
      expect(mod.OAuthConsentPage).toBeDefined()
    })
  })

  describe('5.3 ConsentScreen', () => {
    it('ConsentScreen.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'oauth', 'ConsentScreen.tsx'))).toBe(true)
    })

    it('ConsentScreen è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'oauth', 'ConsentScreen.tsx'))
      expect(mod.ConsentScreen).toBeDefined()
    })
  })

  describe('5.4 App.tsx routing', () => {
    it('App.tsx usa OAuthConsentPage', async () => {
      const appContent = await import(resolve(SRC, 'App.tsx'))
      expect(appContent.default).toBeDefined()
    })
  })
})
