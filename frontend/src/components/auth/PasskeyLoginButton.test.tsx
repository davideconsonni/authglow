// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PasskeyLoginButton } from './PasskeyLoginButton'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockAuthState = vi.hoisted(() => ({
  setAuthenticated: vi.fn(),
  fetchCurrentUser: vi.fn(),
}))
vi.mock('../../stores/authStore', () => ({
  useAuthStore: (selector?: (s: typeof mockAuthState) => unknown) =>
    selector ? selector(mockAuthState) : mockAuthState,
}))

const mockLoginStorage = vi.hoisted(() => ({
  saved: '',
  getSavedEmail: vi.fn(() => mockLoginStorage.saved),
  saveEmail: vi.fn(),
}))
vi.mock('../../lib/loginStorage', () => ({
  getSavedEmail: mockLoginStorage.getSavedEmail,
  saveEmail: mockLoginStorage.saveEmail,
}))

const mockWebauthn = vi.hoisted(() => ({ startAuthentication: vi.fn() }))
vi.mock('@simplewebauthn/browser', () => ({
  startAuthentication: mockWebauthn.startAuthentication,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockLoginStorage.saved = ''
  mockWebauthn.startAuthentication.mockResolvedValue({
    id: 'cred-1',
    response: {
      clientDataJSON: 'cd',
      authenticatorData: 'ad',
      signature: 'sig',
      userHandle: null,
    },
  })
  mockApi.post.mockImplementation(async (endpoint: string) => {
    if (endpoint === '/api/passkey/auth/begin') return { challenge: 'c' }
    return { access_token: 'at-1' }
  })
})

describe('PasskeyLoginButton', () => {
  it('shows the email field when none is saved and signs in', async () => {
    render(<PasskeyLoginButton />)
    const email = screen.getByLabelText('Email for passkey login')
    fireEvent.change(email, { target: { value: 'user@example.com' } })
    fireEvent.click(screen.getByText('Sign in with Passkey'))
    await waitFor(() => expect(mockAuthState.setAuthenticated).toHaveBeenCalledWith(true))
    expect(mockLoginStorage.saveEmail).toHaveBeenCalledWith('user@example.com')
    expect(mockApi.post).toHaveBeenCalledWith('/api/passkey/auth/begin', {
      email: 'user@example.com',
    })
    expect(mockApi.post).toHaveBeenCalledWith(
      '/api/passkey/auth/complete',
      expect.objectContaining({ credential_id: 'cred-1' }),
    )
  })

  it('hides the email field when an email is saved', async () => {
    mockLoginStorage.saved = 'saved@example.com'
    render(<PasskeyLoginButton />)
    expect(screen.queryByLabelText('Email for passkey login')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('Sign in with Passkey'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/passkey/auth/begin', {
        email: 'saved@example.com',
      }),
    )
  })

  it('maps a "name" error to a friendly message', async () => {
    mockWebauthn.startAuthentication.mockRejectedValueOnce(new Error('Unknown device name'))
    render(<PasskeyLoginButton />)
    fireEvent.change(screen.getByLabelText('Email for passkey login'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByText('Sign in with Passkey'))
    await screen.findByText('No passkey found for this device.')
  })

  it('shows other errors verbatim', async () => {
    mockWebauthn.startAuthentication.mockRejectedValueOnce(new Error('network down'))
    render(<PasskeyLoginButton />)
    fireEvent.change(screen.getByLabelText('Email for passkey login'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByText('Sign in with Passkey'))
    await screen.findByText('network down')
  })
})
