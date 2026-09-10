import { describe, expect, it } from 'vitest'
import { getCodeSnippet, getDocUrl } from './oauthClientSnippets'

const FRAMEWORKS = ['nextjs', 'react', 'python', 'node', 'go', 'dotnet']
const CLIENT = { client_id: 'cid-123', client_secret: 's3cr3t' }

describe('oauthClientSnippets — getCodeSnippet', () => {
  it.each(FRAMEWORKS)('framework %s returns a fully-rendered snippet', (fw) => {
    const snippet = getCodeSnippet(fw, CLIENT)
    expect(snippet.length).toBeGreaterThan(0)
    expect(snippet).not.toContain('__CLIENT_ID__')
    expect(snippet).not.toContain('__CLIENT_SECRET__')
    expect(snippet).not.toContain('__BASE_URL__')
    expect(snippet).not.toContain('__SCOPES__')
    expect(snippet).toContain(CLIENT.client_id)
  })

  it('react snippet renders real JSX tags (no unicode escapes)', () => {
    const snippet = getCodeSnippet('react', CLIENT)
    expect(snippet).toContain('<AuthGlowProvider')
    expect(snippet).toContain('<App />')
    expect(snippet).toContain('</AuthGlowProvider>')
    expect(snippet).not.toContain('\\u003c')
  })

  it('secret-bearing snippets include the client secret', () => {
    for (const fw of ['nextjs', 'python', 'node', 'go', 'dotnet']) {
      expect(getCodeSnippet(fw, CLIENT)).toContain(CLIENT.client_secret)
    }
  })

  it('unknown framework returns empty string', () => {
    expect(getCodeSnippet('cobol', CLIENT)).toBe('')
  })
})

describe('oauthClientSnippets — getDocUrl', () => {
  it.each(FRAMEWORKS)('framework %s has a docs url', (fw) => {
    expect(getDocUrl(fw)).toMatch(/^https?:\/\//)
  })

  it('unknown framework falls back to #', () => {
    expect(getDocUrl('cobol')).toBe('#')
  })
})
