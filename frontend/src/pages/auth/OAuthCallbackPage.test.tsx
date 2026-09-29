// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { OAuthCallbackPage } from './OAuthCallbackPage'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ postForm: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockAuthState = vi.hoisted(() => ({ fetchCurrentUser: vi.fn() }))
vi.mock('../../stores/authStore', () => ({
  useAuthStore: (selector?: (s: typeof mockAuthState) => unknown) =>
    selector ? selector(mockAuthState) : mockAuthState,
}))

vi.mock('../../lib/oauthCrypto', () => ({
  parseAuthorizationCallback: vi.fn(() => 'code-1'),
  readJwtClaim: vi.fn(() => 'nonce-1'),
  PLAYGROUND_TRANSACTION_KEY: 'pg_tx',
}))

const TRANSACTION = {
  clientId: 'c1',
  redirectUri: 'https://app.example/cb',
  state: 'st-1',
  nonce: 'nonce-1',
  codeVerifier: 'verifier-1',
}

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  sessionStorage.setItem('pg_tx', JSON.stringify(TRANSACTION))
  mockApi.postForm.mockResolvedValue({ id_token: 'header.payload.sig' })
})

describe('OAuthCallbackPage', () => {
  it('completes the sign-in and navigates to the dashboard', async () => {
    render(<OAuthCallbackPage />)
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith(ROUTES.DASHBOARD, { replace: true }))
    expect(mockAuthState.fetchCurrentUser).toHaveBeenCalled()
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      expect.objectContaining({ grant_type: 'authorization_code', code: 'code-1' }),
    )
    expect(sessionStorage.getItem('pg_tx')).toBeNull()
  })

  it('honours a custom returnTo', async () => {
    sessionStorage.setItem('pg_tx', JSON.stringify({ ...TRANSACTION, returnTo: '/somewhere' }))
    render(<OAuthCallbackPage />)
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/somewhere', { replace: true }))
  })

  it('errors when the transaction is missing', async () => {
    sessionStorage.clear()
    render(<OAuthCallbackPage />)
    await screen.findByText('Sign-in transaction is missing or expired')
    expect(screen.getByText('Sign-in failed')).toBeInTheDocument()
  })

  it('errors when no ID token is returned', async () => {
    mockApi.postForm.mockResolvedValueOnce({})
    render(<OAuthCallbackPage />)
    await screen.findByText('Sign-in failed: no ID token returned')
  })

  it('errors on a nonce mismatch', async () => {
    const crypto = await import('../../lib/oauthCrypto')
    vi.mocked(crypto.readJwtClaim).mockReturnValueOnce('other-nonce')
    render(<OAuthCallbackPage />)
    await screen.findByText('OIDC nonce validation failed')
  })

  it('returns to sign in from the error state', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('boom'))
    render(<OAuthCallbackPage />)
    const button = await screen.findByText('Return to sign in')
    fireEvent.click(button)
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.LOGIN, { replace: true })
  })
})
