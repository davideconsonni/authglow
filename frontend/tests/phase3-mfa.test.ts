import { describe, it, expect } from 'vitest'
import { existsSync } from 'node:fs'
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
