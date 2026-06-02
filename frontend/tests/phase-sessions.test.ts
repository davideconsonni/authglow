import { describe, it, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')
const SRC = resolve(ROOT, 'src')
const PAGE = resolve(SRC, 'pages', 'SessionsPage.tsx')

describe('Sessions — Frontend', () => {
  it('SessionsPage.tsx esiste', () => {
    expect(existsSync(PAGE)).toBe(true)
  })

  it('SessionsPage è importabile', async () => {
    const mod = await import(PAGE)
    expect(mod.SessionsPage).toBeDefined()
  })

  it('chiama l\'endpoint di lista corretto', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('/api/tokens/refresh/list')
  })

  it('chiama l\'endpoint di revoke-all', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('/api/tokens/refresh/revoke-all')
  })

  it('interfaccia Session con campi attesi', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('id: string')
    expect(source).toContain('client: string')
    expect(source).toContain('ip_address: string')
    expect(source).toContain('created_at: string')
    expect(source).toContain('last_active: string')
  })

  it('gestisce più shape di risposta (array, sessions, items, tokens)', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('Array.isArray(rawData)')
    expect(source).toContain('rawData?.sessions')
    expect(source).toContain('rawData?.items')
    expect(source).toContain('rawData?.tokens')
  })

  it('NON contiene più il copy fuorviante sulle sessioni di login diretto', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).not.toContain('Direct login sessions')
    expect(source).not.toContain('do not appear here')
  })

  it('mostra la tabella con colonne Client, IP, Created, Last Active', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('>Client<')
    expect(source).toContain('>IP Address<')
    expect(source).toContain('>Created<')
    expect(source).toContain('>Last Active<')
  })

  it('ha handler handleRevokeAll', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('handleRevokeAll')
  })

  it('usa useApiQuery per il fetch', async () => {
    const source = readFileSync(PAGE, 'utf-8')
    expect(source).toContain('useApiQuery')
    expect(source).toContain("['my-sessions']")
  })
})
