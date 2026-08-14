import { describe, expect, it } from 'vitest'
import {
  generateOAuthNonce,
  generateOAuthState,
  generatePkceChallenge,
  generatePkceVerifier,
  parseAuthorizationCallback,
  readJwtClaim,
} from './oauthCrypto'

describe('oauth crypto helpers', () => {
  it('generates high-entropy URL-safe state and nonce values', () => {
    const state = generateOAuthState()
    const nonce = generateOAuthNonce()

    expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(state).not.toBe(nonce)
  })

  it('generates an RFC 7636-compatible verifier and challenge', async () => {
    const verifier = generatePkceVerifier()
    const challenge = await generatePkceChallenge(verifier)

    expect(verifier).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(challenge).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('reads claims from a JWT payload without treating it as trusted', () => {
    const payload = btoa(JSON.stringify({ nonce: 'expected-nonce' }))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '')

    expect(readJwtClaim('header.' + payload + '.signature', 'nonce')).toBe('expected-nonce')
    expect(readJwtClaim('not-a-jwt', 'nonce')).toBeUndefined()
  })

  it('validates callback origin, path, state, and extracts the code', () => {
    expect(
      parseAuthorizationCallback(
        'https://client.example/callback?code=auth-code&state=expected',
        'https://client.example/callback',
        'expected',
      ),
    ).toBe('auth-code')

    expect(() =>
      parseAuthorizationCallback(
        'https://client.example/callback?code=auth-code&state=wrong',
        'https://client.example/callback',
        'expected',
      ),
    ).toThrow('state validation failed')
  })
})
