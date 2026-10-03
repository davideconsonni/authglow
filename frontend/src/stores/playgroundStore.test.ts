// @vitest-environment jsdom
import { describe, it, expect, beforeEach } from 'vitest'
import {
  usePlaygroundStore,
  generateState,
  generatePkceVerifier,
  generatePkceChallenge,
} from './playgroundStore'

const INITIAL = usePlaygroundStore.getState()

function resetStore() {
  usePlaygroundStore.setState({
    currentFlow: 'authorization-code',
    accessToken: '',
    refreshToken: '',
    idToken: '',
    clientId: '',
    clientSecret: '',
    codeVerifier: '',
    codeChallenge: '',
    authCode: '',
    redirectUri: '',
    scopes: 'openid profile email offline_access',
    state: 'state-1',
    nonce: 'nonce-1',
    apiKey: '',
    responseData: null,
  })
}

beforeEach(resetStore)

describe('playgroundStore defaults', () => {
  it('starts on authorization-code with generated state and nonce', () => {
    expect(INITIAL.currentFlow).toBe('authorization-code')
    expect(INITIAL.scopes).toBe('openid profile email offline_access')
    expect(INITIAL.state.length).toBeGreaterThan(10)
    expect(INITIAL.nonce.length).toBeGreaterThan(10)
    expect(INITIAL.responseData).toBeNull()
  })
})

describe('playgroundStore setters', () => {
  it('updates every field', () => {
    const s = usePlaygroundStore.getState()
    s.setCurrentFlow('pkce')
    s.setAccessToken('at')
    s.setRefreshToken('rt')
    s.setIdToken('id')
    s.setClientId('client')
    s.setClientSecret('secret')
    s.setCodeVerifier('verifier')
    s.setCodeChallenge('challenge')
    s.setAuthCode('code')
    s.setRedirectUri('https://app.example/cb')
    s.setScopes('openid')
    s.setState('st')
    s.setNonce('no')
    s.setApiKey('ak')
    s.setResponseData('{"ok":true}')

    expect(usePlaygroundStore.getState()).toMatchObject({
      currentFlow: 'pkce',
      accessToken: 'at',
      refreshToken: 'rt',
      idToken: 'id',
      clientId: 'client',
      clientSecret: 'secret',
      codeVerifier: 'verifier',
      codeChallenge: 'challenge',
      authCode: 'code',
      redirectUri: 'https://app.example/cb',
      scopes: 'openid',
      state: 'st',
      nonce: 'no',
      apiKey: 'ak',
      responseData: '{"ok":true}',
    })
  })
})

describe('persistTokens', () => {
  it('stores the provided tokens', () => {
    usePlaygroundStore.getState().persistTokens('at', 'rt', 'id')
    expect(usePlaygroundStore.getState()).toMatchObject({
      accessToken: 'at',
      refreshToken: 'rt',
      idToken: 'id',
    })
  })

  it('keeps the existing tokens when arguments are omitted', () => {
    usePlaygroundStore.getState().persistTokens('at', 'rt', 'id')
    usePlaygroundStore.getState().persistTokens()
    expect(usePlaygroundStore.getState()).toMatchObject({
      accessToken: 'at',
      refreshToken: 'rt',
      idToken: 'id',
    })
  })
})

describe('clearAll', () => {
  it('clears the transaction data and regenerates the nonce', () => {
    const s = usePlaygroundStore.getState()
    s.setAccessToken('at')
    s.setRefreshToken('rt')
    s.setIdToken('id')
    s.setClientId('client')
    s.setClientSecret('secret')
    s.setCodeVerifier('verifier')
    s.setCodeChallenge('challenge')
    s.setAuthCode('code')
    s.setRedirectUri('uri')
    s.setApiKey('ak')
    s.setResponseData('data')

    usePlaygroundStore.getState().clearAll()

    const next = usePlaygroundStore.getState()
    expect(next).toMatchObject({
      accessToken: '',
      refreshToken: '',
      idToken: '',
      clientId: '',
      clientSecret: '',
      codeVerifier: '',
      codeChallenge: '',
      authCode: '',
      redirectUri: '',
      apiKey: '',
      responseData: null,
    })
    expect(next.nonce).not.toBe('nonce-1')
    expect(next.nonce.length).toBeGreaterThan(10)
  })
})

describe('re-exported helpers', () => {
  it('exposes the oauth crypto helpers', () => {
    expect(typeof generatePkceChallenge).toBe('function')
    expect(typeof generatePkceVerifier()).toBe('string')
    expect(generatePkceVerifier()).not.toBe(generatePkceVerifier())
    expect(generateState().length).toBeGreaterThan(10)
  })
})