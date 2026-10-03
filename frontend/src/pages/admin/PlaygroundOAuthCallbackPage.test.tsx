// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { PlaygroundOAuthCallbackPage } from './PlaygroundOAuthCallbackPage'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ postForm: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockStore = vi.hoisted(() => ({ persistTokens: vi.fn() }))
vi.mock('../../stores/playgroundStore', () => ({
  usePlaygroundStore: (selector?: (s: typeof mockStore) => unknown) =>
    selector ? selector(mockStore) : mockStore,
}))

const mockCrypto = vi.hoisted(() => ({ parse: vi.fn(), readClaim: vi.fn() }))
vi.mock('../../lib/oauthCrypto', () => ({
  PLAYGROUND_TRANSACTION_KEY: 'pg-tx',
  parseAuthorizationCallback: mockCrypto.parse,
  readJwtClaim: mockCrypto.readClaim,
}))

const TX = {
  clientId: 'client-1',
  clientSecret: 'secret-1',
  redirectUri: 'https://app/cb',
  scopes: 'openid profile',
  state: 'st',
  nonce: 'nonce-1',
  codeVerifier: 'verifier-1',
}

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  mockCrypto.parse.mockReturnValue('auth-code')
  mockCrypto.readClaim.mockReturnValue('nonce-1')
  mockApi.postForm.mockResolvedValue({
    access_token: 'at',
    refresh_token: 'rt',
    id_token: 'idt',
  })
})

describe('PlaygroundOAuthCallbackPage', () => {
  it('fails when the transaction is missing', async () => {
    render(<PlaygroundOAuthCallbackPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'OAuth playground transaction is missing or expired',
    )
  })

  it('exchanges the code, validates the nonce and persists the tokens', async () => {
    sessionStorage.setItem('pg-tx', JSON.stringify(TX))
    render(<PlaygroundOAuthCallbackPage />)

    expect(await screen.findByText('OAuth authorization complete')).toBeInTheDocument()
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      expect.objectContaining({ code: 'auth-code', code_verifier: 'verifier-1' }),
      { headers: { Authorization: `Basic ${btoa('client-1:secret-1')}` } },
    )
    expect(mockStore.persistTokens).toHaveBeenCalledWith('at', 'rt', 'idt')
    expect(sessionStorage.getItem('pg-tx')).toBeNull()

    fireEvent.click(screen.getByText('Return to playground'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.PLAYGROUND)
  })

  it('rejects a nonce mismatch', async () => {
    mockCrypto.readClaim.mockReturnValue('other-nonce')
    sessionStorage.setItem('pg-tx', JSON.stringify(TX))
    render(<PlaygroundOAuthCallbackPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent('OIDC nonce validation failed')
    expect(mockStore.persistTokens).not.toHaveBeenCalled()
  })

  it('omits the Basic header without a client secret and skips nonce for non-OIDC', async () => {
    sessionStorage.setItem(
      'pg-tx',
      JSON.stringify({ ...TX, clientSecret: undefined, scopes: 'profile' }),
    )
    render(<PlaygroundOAuthCallbackPage />)
    await screen.findByText('OAuth authorization complete')
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      expect.any(Object),
      { headers: undefined },
    )
  })

  it('surfaces a token-exchange failure', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('token boom'))
    sessionStorage.setItem('pg-tx', JSON.stringify(TX))
    render(<PlaygroundOAuthCallbackPage />)
    expect(await screen.findByRole('alert')).toHaveTextContent('token boom')
  })
})