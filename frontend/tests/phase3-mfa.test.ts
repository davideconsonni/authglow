import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')

describe('Fase 3 — MFA (TOTP, Backup Codes, Trusted Devices)', () => {
  describe('3.1 MFAVerifyForm', () => {
    it('MFAVerifyForm.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'auth', 'MFAVerifyForm.tsx'))).toBe(true)
    })

    it('MFAVerifyForm è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'auth', 'MFAVerifyForm.tsx'))
      expect(mod.MFAVerifyForm).toBeDefined()
    })
  })

  describe('3.2 MFAVerifyPage', () => {
    it('MFAVerifyPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'auth', 'MFAVerifyPage.tsx'))).toBe(true)
    })

    it('MFAVerifyPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'auth', 'MFAVerifyPage.tsx'))
      expect(mod.MFAVerifyPage).toBeDefined()
    })
  })

  describe('3.3 SecurityPage', () => {
    it('SecurityPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'SecurityPage.tsx'))).toBe(true)
    })

    it('SecurityPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'SecurityPage.tsx'))
      expect(mod.SecurityPage).toBeDefined()
    })
  })

  describe('3.4 MFAEnrollment', () => {
    it('MFAEnrollment.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'profile', 'MFAEnrollment.tsx'))).toBe(true)
    })

    it('MFAEnrollment è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'profile', 'MFAEnrollment.tsx'))
      expect(mod.MFAEnrollment).toBeDefined()
    })

    it('usa il campo qr_code (non qr_code_base64) per matchare il backend', () => {
      const source = readFileSync(resolve(SRC, 'components', 'profile', 'MFAEnrollment.tsx'), 'utf-8')
      expect(source).toContain('qr_code: string')
      expect(source).toContain('enrollmentData.qr_code')
      expect(source).not.toContain('qr_code_base64')
    })

    it('usa enrollmentData.qr_code direttamente come src (backend ritorna già il data URL completo)', () => {
      const source = readFileSync(resolve(SRC, 'components', 'profile', 'MFAEnrollment.tsx'), 'utf-8')
      expect(source).toContain('src={enrollmentData.qr_code}')
      expect(source).not.toContain('data:image/png;base64,${enrollmentData.qr_code}')
    })

    it('chiama /api/mfa/enroll', () => {
      const source = readFileSync(resolve(SRC, 'components', 'profile', 'MFAEnrollment.tsx'), 'utf-8')
      expect(source).toContain("'/api/mfa/enroll'")
    })
  })

  describe('3.5 BackupCodes', () => {
    it('BackupCodes.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'profile', 'BackupCodes.tsx'))).toBe(true)
    })

    it('BackupCodes è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'profile', 'BackupCodes.tsx'))
      expect(mod.BackupCodes).toBeDefined()
    })
  })

  describe('3.6 TrustedDevices', () => {
    it('TrustedDevices.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'components', 'profile', 'TrustedDevices.tsx'))).toBe(true)
    })

    it('TrustedDevices è importabile', async () => {
      const mod = await import(resolve(SRC, 'components', 'profile', 'TrustedDevices.tsx'))
      expect(mod.TrustedDevices).toBeDefined()
    })
  })
})
