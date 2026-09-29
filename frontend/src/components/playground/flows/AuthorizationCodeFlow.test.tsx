// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AuthorizationCodeFlow } from './AuthorizationCodeFlow'

const mockStore = vi.hoisted(() => ({
  clientId: 'test-client',
  clientSecret: 'test-secret',
  redirectUri: 'https://app.example/cb',
  scopes: 'openid profile',
  state: 'st-1',
  authCode: 'code-1',
  nonce: 'nonce-1',
  codeVerifier: '',
  codeChallenge: '',
  accessToken: '',
  refreshToken: '',
  apiKey: '',
  setClientId: vi.fn(),
  setClientSecret: vi.fn(),
  setRedirectUri: vi.fn(),
  setScopes: vi.fn(),
  setState: vi.fn(),
  setNonce: vi.fn(),
  setAuthCode: vi.fn(),
  setCodeVerifier: vi.fn(),
  setCodeChallenge: vi.fn(),
  setAccessToken: vi.fn(),
  setRefreshToken: vi.fn(),
  setApiKey: vi.fn(),
  persistTokens: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({
  usePlaygroundStore: () => mockStore,
  generateState: () => 'generated-state',
}))

const mockApi = vi.hoisted(() => ({
  postForm: vi.fn(),
  post: vi.fn(),
  get: vi.fn(async () => ({ scopes: [] })),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

vi.mock('../../../lib/oauthCrypto', () => ({
  generateOAuthNonce: () => 'nonce-1',
  generatePkceVerifier: () => 'verifier-1',
  generatePkceChallenge: async () => 'challenge-1',
  parseAuthorizationCallback: vi.fn(() => 'parsed-code'),
  readJwtClaim: vi.fn(() => 'nonce-1'),
  PLAYGROUND_TRANSACTION_KEY: 'pg_tx',
}))

async function reachCodeStep() {
  render(<AuthorizationCodeFlow />)
  fireEvent.click(screen.getByTestId('playground-config-next'))
  await screen.findByText('I have the code')
  fireEvent.click(screen.getByText('I have the code'))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.postForm.mockResolvedValue({ access_token: 'at-1', refresh_token: 'rt-1' })
})

describe('AuthorizationCodeFlow', () => {
  it('renders the configure step and advances to authorize', async () => {
    render(<AuthorizationCodeFlow />)
    expect(screen.getByText('Client ID *')).toBeInTheDocument()
    expect(screen.getByText('Redirect URI *')).toBeInTheDocument()
    fireEvent.click(screen.getByTitle('Regenerate state'))
    expect(mockStore.setClientId).toBeDefined()

    fireEvent.click(screen.getByTestId('playground-config-next'))
    await screen.findByText('I have the code')
    expect(mockStore.setClientId).toHaveBeenCalledWith('test-client')
    expect(sessionStorage.getItem('pg_tx')).toBeTruthy()
  })

  it('exchanges a pasted code for tokens', async () => {
    await reachCodeStep()
    fireEvent.change(screen.getByTestId('playground-auth-code'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByTestId('playground-exchange-code'))
    await screen.findByText(/Tokens obtained and auto-saved/)
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      expect.objectContaining({ grant_type: 'authorization_code', code: 'abc' }),
      { headers: { Authorization: `Basic ${btoa('test-client:test-secret')}` } },
    )
    expect(mockStore.persistTokens).toHaveBeenCalled()
  })

  it('parses a pasted callback URL', async () => {
    const crypto = await import('../../../lib/oauthCrypto')
    await reachCodeStep()
    fireEvent.change(screen.getByTestId('playground-callback-url'), {
      target: { value: 'https://app.example/cb?code=x&state=st-1' },
    })
    fireEvent.click(screen.getByTestId('playground-exchange-code'))
    await screen.findByText(/Tokens obtained and auto-saved/)
    expect(vi.mocked(crypto.parseAuthorizationCallback)).toHaveBeenCalled()
  })

  it('fails OIDC nonce validation', async () => {
    const crypto = await import('../../../lib/oauthCrypto')
    vi.mocked(crypto.readJwtClaim).mockReturnValueOnce('wrong-nonce')
    await reachCodeStep()
    fireEvent.change(screen.getByTestId('playground-auth-code'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByTestId('playground-exchange-code'))
    await screen.findByText('OIDC nonce validation failed')
  })

  it('surfaces an exchange error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('bad code'))
    await reachCodeStep()
    fireEvent.change(screen.getByTestId('playground-auth-code'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByTestId('playground-exchange-code'))
    await screen.findByText('bad code')
  })

  it('resets to the configure step', async () => {
    await reachCodeStep()
    fireEvent.change(screen.getByTestId('playground-auth-code'), { target: { value: 'abc' } })
    fireEvent.click(screen.getByTestId('playground-exchange-code'))
    await screen.findByText(/Tokens obtained and auto-saved/)
    fireEvent.click(screen.getByText('Start Over'))
    expect(screen.getByText('Client ID *')).toBeInTheDocument()
  })
})
