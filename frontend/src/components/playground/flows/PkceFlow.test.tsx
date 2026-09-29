// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { PkceFlow } from './PkceFlow'

const mockStore = vi.hoisted(() => ({
  clientId: 'pkce-client',
  redirectUri: 'https://app.example/cb',
  scopes: 'openid profile',
  state: 'st-1',
  nonce: 'nonce-1',
  codeVerifier: '',
  codeChallenge: '',
  accessToken: '',
  refreshToken: '',
  apiKey: '',
  clientSecret: '',
  setClientId: vi.fn(),
  setRedirectUri: vi.fn(),
  setScopes: vi.fn(),
  setState: vi.fn(),
  setNonce: vi.fn(),
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
  generatePkceVerifier: () => 'pkce-verifier',
  generatePkceChallenge: async () => 'pkce-challenge',
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
  parseAuthorizationCallback: vi.fn(() => 'parsed-code'),
  readJwtClaim: vi.fn(() => 'nonce-1'),
  PLAYGROUND_TRANSACTION_KEY: 'pg_tx',
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.postForm.mockResolvedValue({ access_token: 'at-1' })
})

describe('PkceFlow', () => {
  it('walks config → pkce → authorize → exchange → tokens', async () => {
    render(<PkceFlow />)
    expect(screen.getByText(/PKCE \(Proof Key for Code Exchange\)/)).toBeInTheDocument()

    fireEvent.click(screen.getByText('Next'))
    expect(screen.getByText('Code Verifier (auto-generated)')).toBeInTheDocument()

    fireEvent.click(screen.getByText(/Generate PKCE & Continue/))
    await screen.findByText('Open in Browser')
    expect(mockStore.setCodeVerifier).toHaveBeenCalledWith('pkce-verifier')

    fireEvent.click(screen.getByText('I have the code'))
    expect(screen.getByTestId('pkce-callback-url')).toBeInTheDocument()
  })

  it('exchanges the code for tokens and resets', async () => {
    render(<PkceFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByText(/Generate PKCE & Continue/))
    await screen.findByText('I have the code')
    fireEvent.click(screen.getByText('I have the code'))

    fireEvent.change(screen.getByPlaceholderText('Paste code from callback'), {
      target: { value: 'code-x' },
    })
    fireEvent.click(screen.getByText('Exchange Code'))
    await screen.findByText(/Tokens obtained via PKCE/)
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      expect.objectContaining({ code: 'code-x', code_verifier: 'pkce-verifier' }),
    )
    expect(mockStore.persistTokens).toHaveBeenCalled()

    fireEvent.click(screen.getByText('Start Over'))
    expect(screen.getByText(/PKCE \(Proof Key for Code Exchange\)/)).toBeInTheDocument()
  })

  it('surfaces an exchange error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('pkce boom'))
    render(<PkceFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByText(/Generate PKCE & Continue/))
    await screen.findByText('I have the code')
    fireEvent.click(screen.getByText('I have the code'))
    fireEvent.change(screen.getByPlaceholderText('Paste code from callback'), {
      target: { value: 'code-x' },
    })
    fireEvent.click(screen.getByText('Exchange Code'))
    await screen.findByText('pkce boom')
  })
})
