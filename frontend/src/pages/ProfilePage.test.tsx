// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ProfilePage } from './ProfilePage'
import { ROUTES } from '../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn().mockResolvedValue({}),
  patch: vi.fn().mockResolvedValue({}),
  delete: vi.fn().mockResolvedValue({}),
}))
vi.mock('../lib/api', () => ({ api: mockApi }))

const mockAuth = vi.hoisted(() => ({
  user: null as Record<string, unknown> | null,
  fetchCurrentUser: vi.fn().mockResolvedValue(undefined),
  logout: vi.fn().mockResolvedValue(undefined),
}))
vi.mock('../hooks/useAuth', () => ({ useAuth: () => mockAuth }))

const mockQuery = vi.hoisted(() => ({ data: undefined as unknown }))
vi.mock('../hooks/useApi', () => ({ useApiQuery: () => ({ data: mockQuery.data }) }))

vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

// Heavy children with their own API/safeword flows are out of scope here.
vi.mock('../components/auth/PhoneVerificationCard', () => ({
  PhoneVerificationCard: () => <div data-testid="phone-card" />,
}))
vi.mock('../components/auth/ResendVerificationBanner', () => ({
  ResendVerificationBanner: () => <div data-testid="resend-banner" />,
}))
vi.mock('../components/admin/RotateSecretDialog', () => ({
  RotateSecretDialog: ({
    open,
    onSuccess,
    onError,
  }: {
    open: boolean
    onSuccess: () => void | Promise<void>
    onError: (message: string) => void
  }) =>
    open ? (
      <div data-testid="rsd">
        <button data-testid="rsd-success" onClick={() => void onSuccess()}>
          success
        </button>
        <button data-testid="rsd-error" onClick={() => onError('boom')}>
          error
        </button>
      </div>
    ) : null,
}))

function makeUser(overrides: Record<string, unknown> = {}) {
  return {
    id: 'u1',
    email: 'user@example.com',
    is_active: true,
    created_at: '2026-01-01T00:00:00Z',
    first_name: 'Ada',
    last_name: 'Lovelace',
    scopes: ['read', 'write'],
    mfa_enabled: true,
    mfa_verified: true,
    email_verified: true,
    phone: '+39123',
    phone_verified: true,
    is_bootstrap: false,
    is_federated: false,
    ...overrides,
  }
}

async function importNotify() {
  return (await import('../stores/toastStore')).notify
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.user = makeUser()
  mockQuery.data = undefined
  mockApi.patch.mockResolvedValue({})
  mockApi.post.mockResolvedValue({})
  mockApi.delete.mockResolvedValue({})
})

describe('ProfilePage', () => {
  it('renders the identity card from the authenticated user', () => {
    render(<ProfilePage />)
    expect(screen.getByText('user@example.com')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Email verified')).toBeInTheDocument()
    expect(screen.getByText('Phone verified')).toBeInTheDocument()
    expect(screen.getByText('+39123')).toBeInTheDocument()
    expect(screen.getByTestId('phone-card')).toBeInTheDocument()
    expect(screen.getByText('read')).toBeInTheDocument()
    expect(screen.getByText('write')).toBeInTheDocument()
    expect(screen.getByText('u1')).toBeInTheDocument()
  })

  it('falls back to the queried profile when there is no session user', () => {
    mockAuth.user = null
    mockQuery.data = makeUser({ email: 'from-query@example.com' })
    render(<ProfilePage />)
    expect(screen.getByText('from-query@example.com')).toBeInTheDocument()
  })

  it('shows a placeholder when the creation date is missing', () => {
    mockAuth.user = makeUser({ created_at: '' })
    render(<ProfilePage />)
    expect(screen.getByText('Member since -')).toBeInTheDocument()
  })

  it('shows the resend banner when the email is not verified', () => {
    mockAuth.user = makeUser({ email_verified: false })
    render(<ProfilePage />)
    expect(screen.getByTestId('resend-banner')).toBeInTheDocument()
    expect(screen.getByText('Email not verified')).toBeInTheDocument()
  })

  it('hides phone details when no phone is set', () => {
    mockAuth.user = makeUser({ phone: null, phone_verified: undefined })
    render(<ProfilePage />)
    expect(screen.queryByText('No phone number')).not.toBeInTheDocument()
    expect(screen.queryByText('Phone verified')).not.toBeInTheDocument()
  })

  it('shows an empty permissions state and no copy button without an id', () => {
    mockAuth.user = makeUser({ id: '', scopes: [] })
    render(<ProfilePage />)
    expect(screen.getByText('No permissions assigned.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Copy')).not.toBeInTheDocument()
  })

  it('navigates through the quick links', () => {
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Security'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SECURITY)
    fireEvent.click(screen.getByText('Sessions'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SESSIONS)
    fireEvent.click(screen.getByText('API Keys'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.API_KEYS)
  })

  it('edits the name and saves it', async () => {
    const notify = await importNotify()
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Edit'))
    fireEvent.change(screen.getByDisplayValue('Ada'), { target: { value: 'Grace' } })
    fireEvent.click(screen.getByText('Save changes'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith('/api/profile/me', {
        first_name: 'Grace',
        last_name: 'Lovelace',
      }),
    )
    expect(mockAuth.fetchCurrentUser).toHaveBeenCalled()
    expect(notify.success).toHaveBeenCalledWith('Profile updated successfully.')
    await waitFor(() => expect(screen.queryByText('Save changes')).not.toBeInTheDocument())
  })

  it('cancels the edit form', () => {
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Edit'))
    expect(screen.getByText('Save changes')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByText('Save changes')).not.toBeInTheDocument()
  })

  it('shows the API error when saving fails', async () => {
    mockApi.patch.mockRejectedValueOnce(new Error('update rejected'))
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Edit'))
    fireEvent.click(screen.getByText('Save changes'))
    await screen.findByText('update rejected')
  })

  it('falls back to a generic error for non-Error save failures', async () => {
    mockApi.patch.mockRejectedValueOnce('nope')
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Edit'))
    fireEvent.click(screen.getByText('Save changes'))
    await screen.findByText('Failed to update')
  })

  it('deactivates the account through the safeword dialog', async () => {
    const notify = await importNotify()
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Deactivate'))
    fireEvent.click(screen.getByTestId('rsd-success'))
    await waitFor(() =>
      expect(notify.success).toHaveBeenCalledWith('Account deactivated. You have been signed out.'),
    )
    expect(mockAuth.logout).toHaveBeenCalled()
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.LOGIN)
  })

  it('blocks deactivation for the bootstrap admin', () => {
    mockAuth.user = makeUser({ is_bootstrap: true })
    render(<ProfilePage />)
    expect(screen.getByText('Bootstrap Admin')).toBeInTheDocument()
    expect(screen.queryByText('Deactivate')).not.toBeInTheDocument()
  })

  it('reactivates an inactive account', async () => {
    const notify = await importNotify()
    mockAuth.user = makeUser({ is_active: false })
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Reactivate'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalledWith('/api/profile/me/reactivate'))
    expect(notify.success).toHaveBeenCalledWith('Account reactivated.')
    expect(mockAuth.fetchCurrentUser).toHaveBeenCalled()
  })

  it('reports a reactivation failure', async () => {
    const notify = await importNotify()
    mockAuth.user = makeUser({ is_active: false })
    mockApi.post.mockRejectedValueOnce(new Error('reactivate failed'))
    render(<ProfilePage />)
    fireEvent.click(screen.getByText('Reactivate'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('reactivate failed'))
  })

  it('deletes the account after confirmation', async () => {
    const notify = await importNotify()
    render(<ProfilePage />)
    fireEvent.click(screen.getByRole('button', { name: 'Delete Account' }))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalledWith('/api/profile/me'))
    expect(notify.success).toHaveBeenCalledWith('Account deleted.')
    expect(mockAuth.logout).toHaveBeenCalled()
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.LOGIN)
  })

  it('reports a delete failure', async () => {
    const notify = await importNotify()
    mockApi.delete.mockRejectedValueOnce(new Error('delete failed'))
    render(<ProfilePage />)
    fireEvent.click(screen.getByRole('button', { name: 'Delete Account' }))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('delete failed'))
  })

  it('hides the danger zone for federated accounts', () => {
    mockAuth.user = makeUser({ is_federated: true })
    render(<ProfilePage />)
    expect(screen.getByText('Account Management')).toBeInTheDocument()
    expect(screen.queryByText('Danger Zone')).not.toBeInTheDocument()
  })
})
