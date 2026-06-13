import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')
const BACKEND_TPL = resolve(ROOT, '..', 'backend', 'authglow', 'templates', 'emails')

describe('VAPT-022 — Password reset token must NOT be in URLs', () => {
  describe('ResetPasswordForm.tsx', () => {
    const formPath = resolve(SRC, 'components', 'auth', 'ResetPasswordForm.tsx')
    const formSource = readFileSync(formPath, 'utf8')

    it('ResetPasswordForm.tsx esiste', () => {
      expect(existsSync(formPath)).toBe(true)
    })

    it('NON usa useSearchParams per leggere il token', () => {
      // VAPT-022: il token non deve MAI passare per l'URL (browser history,
      // Referer, proxy logs). Il form deve chiedere il reset_code via input.
      expect(formSource).not.toMatch(/useSearchParams/)
      expect(formSource).not.toMatch(/searchParams\.get\(['"]token['"]\)/)
    })

    it('invia reset_code nel body della richiesta, non un "token"', () => {
      expect(formSource).toMatch(/reset_code\s*:/)
      // Non deve inviare il campo "token" (legacy)
      const apiCallMatch = formSource.match(/api\.post\([^)]*\{([\s\S]*?)\}/)
      expect(apiCallMatch).not.toBeNull()
      const body = apiCallMatch![1]
      expect(body).toContain('reset_code')
      expect(body).not.toMatch(/\btoken\s*:/)
    })

    it('ha un input dedicato per il reset_code (no auto-fill da URL)', () => {
      expect(formSource).toMatch(/register\(['"]reset_code['"]\)/)
      // Il pattern del reset_code: XXXX-XXXX-XXXX
      expect(formSource).toMatch(/XXXX-XXXX-XXXX/)
    })
  })

  describe('ResetPasswordPage.tsx', () => {
    it('esiste e non propaga il token via params', () => {
      const pagePath = resolve(SRC, 'pages', 'auth', 'ResetPasswordPage.tsx')
      const pageSource = readFileSync(pagePath, 'utf8')
      expect(existsSync(pagePath)).toBe(true)
      expect(pageSource).not.toMatch(/useParams\(\)/)
      expect(pageSource).not.toMatch(/useSearchParams\(\)/)
    })
  })

  describe('email templates', () => {
    it('password_reset.html NON contiene reset_url con token', () => {
      const htmlPath = resolve(BACKEND_TPL, 'password_reset.html')
      const html = readFileSync(htmlPath, 'utf8')
      expect(html).not.toMatch(/\{\{\s*reset_url\s*\}\}/)
    })

    it('password_reset.html mostra il reset_code in un blocco visibile', () => {
      const htmlPath = resolve(BACKEND_TPL, 'password_reset.html')
      const html = readFileSync(htmlPath, 'utf8')
      expect(html).toMatch(/\{\{\s*reset_code\s*\}\}/)
    })

    it('password_reset.html link a reset_page_url SENZA query string con token', () => {
      const htmlPath = resolve(BACKEND_TPL, 'password_reset.html')
      const html = readFileSync(htmlPath, 'utf8')
      expect(html).toMatch(/href="\{\{\s*reset_page_url\s*\}\}"/)
      // Non deve concatenare ?token=... all'URL
      expect(html).not.toMatch(/\?token=/)
    })

    it('password_reset.txt NON contiene reset_url con token', () => {
      const txtPath = resolve(BACKEND_TPL, 'password_reset.txt')
      const txt = readFileSync(txtPath, 'utf8')
      expect(txt).not.toMatch(/\{\{\s*reset_url\s*\}\}/)
      expect(txt).toMatch(/\{\{\s*reset_code\s*\}\}/)
      expect(txt).toMatch(/\{\{\s*reset_page_url\s*\}\}/)
    })
  })
})
