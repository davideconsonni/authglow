// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SecurityPage } from './SecurityPage'

const mockApi = vi.hoisted(() => ({ post: vi.fn(), delete: vi.fn() }))
const mockAuth = vi.hoisted(() => ({
  user: null as Record<string, unknown> | null,
  fetchCurrentUser: vi.fn(),
}))
const mockQuery = vi.hoisted(() => ({ data: undefined as unknown }))

vi.mock('../lib/api', () => ({ api: mockApi }))
vi.mock('../hooks/useAuth', () => ({ useAuth: () => mockAuth }))
vi.mock('../hooks/useApi', () => ({ useApiQuery: () => ({ data: mockQuery.data }) }))
vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))
vi.mock('../components/profile/MFAEnrollment', () => ({
  MFAEnrollment: () => <div data-testid="mfa-enrollment" />,
}))
vi.mock('../components/profile/BackupCodes', () => ({
  BackupCodes: ({ onRegenerate }: { onRegenerate: () => void }) => (
    <div data-testid="backup-codes">
      <button onClick={onRegenerate}>regen</button>
    </div>
  ),
}))
vi.mock('../components/profile/TrustedDevices', () => ({
  TrustedDevices: () => <div data-testid="trusted-devices" />,
}))
vi.mock('../components/profile/PasskeyManager', () => ({
  PasskeyManager: () => <div data-testid="passkey-manager" />,
}))
vi.mock('../components/profile/ChangePasswordForm', () => ({
  ChangePasswordForm: () => <div data-testid="change-password" />,
}))
vi.mock('../components/profile/ChangeEmailForm', () => ({
  ChangeEmailForm: () => <div data-testid="change-email" />,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.user = { mfa_enabled: false, is_federated: false }
  mockQuery.data = { enabled: false }
  mockApi.post.mockResolvedValue({ backup_codes: [] })
  mockApi.delete.mockResolvedValue({})
})

describe('SecurityPage', () => {
  it('renders the federated view without MFA controls', () => {
    mockAuth.user = { mfa_enabled: true, is_federated: true }
    render(<SecurityPage />)
    expect(screen.getByText('Managed by your identity provider.')).toBeInTheDocument()
    expect(screen.queryByText(/MFA is/)).not.toBeInTheDocument()
    expect(screen.getByTestId('trusted-devices')).toBeInTheDocument()
  })

  it('shows the disabled state and toggles the setup panel', () => {
    render(<SecurityPage />)
    expect(screen.getByText('MFA is not enabled')).toBeInTheDocument()
    expect(screen.getByText('Off')).toBeInTheDocument()
    expect(screen.getByTestId('mfa-enrollment')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByTestId('mfa-enrollment')).not.toBeInTheDocument()
    expect(screen.getByText('Enable')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Enable'))
    expect(screen.getByTestId('mfa-enrollment')).toBeInTheDocument()
  })

  it('shows the enabled state with remaining backup codes', () => {
    mockAuth.user = { mfa_enabled: true, is_federated: false }
    mockQuery.data = { enabled: true, backup_codes_remaining: 3 }
    render(<SecurityPage />)
    expect(screen.getByText('MFA is enabled')).toBeInTheDocument()
    expect(screen.getByText(/3 backup codes remaining/)).toBeInTheDocument()
    expect(screen.getByText('On')).toBeInTheDocument()
    expect(screen.getByText('Disable')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.getByText('Manage')).toBeInTheDocument()
  })

  it('disables MFA through the confirm dialog', async () => {
    const { notify } = await import('../stores/toastStore')
    mockAuth.user = { mfa_enabled: true, is_federated: false }
    render(<SecurityPage />)
    fireEvent.click(screen.getByText('Disable'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalledWith('/api/mfa/disable'))
    expect(notify.success).toHaveBeenCalledWith('Two-factor authentication disabled.')
    expect(mockAuth.fetchCurrentUser).toHaveBeenCalled()
  })

  it('cancels the disable dialog', () => {
    mockAuth.user = { mfa_enabled: true, is_federated: false }
    render(<SecurityPage />)
    fireEvent.click(screen.getByText('Disable'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })

  it('toasts a disable failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockAuth.user = { mfa_enabled: true, is_federated: false }
    mockApi.delete.mockRejectedValueOnce(new Error('disable failed'))
    render(<SecurityPage />)
    fireEvent.click(screen.getByText('Disable'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('disable failed'))
  })

  it('renders the credentials and passkey sections', () => {
    render(<SecurityPage />)
    expect(screen.getByTestId('passkey-manager')).toBeInTheDocument()
    expect(screen.getByTestId('change-password')).toBeInTheDocument()
    expect(screen.getByTestId('change-email')).toBeInTheDocument()
  })
})
