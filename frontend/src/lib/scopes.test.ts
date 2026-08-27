// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import { parseScopeInput } from './scopes'

describe('parseScopeInput', () => {
  it('splits on whitespace per RFC 6749 §3.3', () => {
    expect(parseScopeInput('openid profile email')).toEqual({
      tokens: ['openid', 'profile', 'email'],
      invalid: [],
    })
  })

  it('collapses multiple spaces / tabs / newlines', () => {
    expect(parseScopeInput('  read\t write\n admin  ')).toEqual({
      tokens: ['read', 'write', 'admin'],
      invalid: [],
    })
  })

  it('flags comma-joined input as invalid instead of silently splitting', () => {
    const { tokens, invalid } = parseScopeInput('read,write')
    expect(tokens).toEqual(['read,write'])
    expect(invalid).toEqual(['read,write'])
  })

  it('flags double-quoted tokens as invalid', () => {
    const { invalid } = parseScopeInput('"read" write')
    expect(invalid).toContain('"read"')
  })

  it('returns empty for blank input', () => {
    expect(parseScopeInput('   ')).toEqual({ tokens: [], invalid: [] })
  })
})
