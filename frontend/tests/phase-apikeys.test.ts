import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')

describe('Fase API Keys — Frontend', () => {
  describe('AdminApiKeysPage', () => {
    it('AdminApiKeysPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'))).toBe(true)
    })

    it('AdminApiKeysPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'))
      expect(mod.AdminApiKeysPage).toBeDefined()
    })

    it('contiene handleRevoke', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('handleRevoke')
    })

    it('contiene handleRestore', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('handleRestore')
    })

    it('contiene handleDelete', async () => {
      // The destructive delete is now handled inside the shared
      // <RotateSecretDialog> via a safeword handshake, so the
      // page no longer owns a local handleDelete function — it
      // delegates to the dialog's onSuccess callback. This
      // test asserts the new wiring is in place.
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('RotateSecretDialog')
      expect(source).toContain('purpose="api_key_delete"')
    })

    it('contiene handleCreate', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('handleCreate')
    })

    it('usa key_id come identificatore', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('setRevokeId(k.key_id)')
      expect(source).toContain('setDeleteId(k.key_id)')
      expect(source).toContain('setRestoreId(k.key_id)')
    })

    it('mostra chiave completa dopo creazione', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('createdKey')
      expect(source).toContain('api_key')
    })

    it('interfaccia ApiKeyData corretta', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key_id: string')
      expect(source).toContain('is_active: boolean')
    })
  })

  describe('ApiKeysPage (utente)', () => {
    it('ApiKeysPage.tsx esiste', () => {
      expect(existsSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'))).toBe(true)
    })

    it('ApiKeysPage è importabile', async () => {
      const mod = await import(resolve(SRC, 'pages', 'ApiKeysPage.tsx'))
      expect(mod.ApiKeysPage).toBeDefined()
    })

    it('contiene handleRevoke', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('handleRevoke')
    })

    it('contiene handleRestore', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('handleRestore')
    })

    it('contiene handleDelete', async () => {
      // The destructive delete is now handled inside the shared
      // <RotateSecretDialog> via a safeword handshake, so the
      // page no longer owns a local handleDelete function — it
      // delegates to the dialog's onSuccess callback. This
      // test asserts the new wiring is in place.
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('RotateSecretDialog')
      expect(source).toContain('purpose="api_key_delete"')
    })

    it('usa key_id', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key_id')
      expect(source).toContain('k.key_id')
    })

    it('interfaccia con is_active', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('is_active')
    })

    it('contiene data-testid', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('create-api-key-btn')
      expect(source).toContain('key-name-input')
      expect(source).toContain('key-scopes')
      expect(source).toContain('key-create-submit')
      expect(source).toContain('key-created-display')
      expect(source).toContain('api-key-row')
      expect(source).toContain('revoke-key-btn')
    })

    it('campo allowed_ips esposto nel create modal', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-allowed-ips-input')
      expect(source).toContain('allowed_ips')
    })

    it('warning scope-filter nel success modal', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('scope-filter-warning')
      expect(source).toContain('filtered_scopes')
      expect(source).toContain('requested_scopes')
      expect(source).toContain('granted_scopes')
    })

    it('colonna IP Restriction presente', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('IP Restriction')
      expect(source).toContain('key-ips-display')
    })

    it('campo description in create modal', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-description-input')
      expect(source).toContain('description: newDescription.trim() || null')
    })

    it('description mostrata come sub-text sotto il Name', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-description-display')
      expect(source).toContain('k.description')
    })

    it('edit button e edit modal presenti', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-edit-btn')
      expect(source).toContain('key-edit-modal')
      expect(source).toContain('key-edit-description-input')
      expect(source).toContain('key-edit-submit')
    })

    it('interfaccia ApiKeyData include description', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('description: string | null')
    })
  })

  describe('AdminApiKeysPage — hardening 2026-07', () => {
    it('campo allowed_ips esposto nel create modal admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-allowed-ips-input')
      expect(source).toContain('Restrict to IPs')
    })

    it('warning scope-filter nel success modal admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('scope-filter-warning')
      expect(source).toContain('filtered_scopes')
    })

    it('colonna IP Restriction presente in admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('IP Restriction')
      expect(source).toContain('key-ips-display')
    })

    it('campo description in create modal admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-description-input')
      expect(source).toContain("description: form.description.trim() || null")
    })

    it('description mostrata come sub-text nel Name admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-description-display')
      expect(source).toContain('k.description')
    })

    it('edit button e edit modal presenti admin', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('key-edit-btn')
      expect(source).toContain('key-edit-modal')
      expect(source).toContain('key-edit-description-input')
      expect(source).toContain('key-edit-submit')
    })

    it('rotazione secret via RotateSecretDialog con purpose api_key_rotate', async () => {
      // Regen-secret flow: same safeword dialog shape as delete.
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('purpose="api_key_rotate"')
      expect(source).toContain('setRotateId(k.key_id)')
    })

    it('rotatedKey modal mostra la nuova plaintext una sola volta', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('rotated-key-modal')
      expect(source).toContain('rotated-key-value')
      expect(source).toContain('rotated-key-copy')
      expect(source).toContain('rotated-key-done')
    })

    it('rotatedKey modal include avviso copy-now', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'admin', 'AdminApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('Copy this secret now')
    })
  })

  describe('ApiKeysPage (utente) — rotate secret', () => {
    it('rotazione secret via RotateSecretDialog con purpose api_key_rotate', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('purpose="api_key_rotate"')
      expect(source).toContain('setRotateId(k.key_id)')
    })

    it('rotatedKey modal presente', async () => {
      const source = readFileSync(resolve(SRC, 'pages', 'ApiKeysPage.tsx'), 'utf-8')
      expect(source).toContain('rotated-key-modal')
      expect(source).toContain('rotated-key-value')
    })
  })
})
