// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { DeviceAuthorizationsPage } from './DeviceAuthorizationsPage'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
const mockQuery = vi.hoisted(() => ({
  data: undefined as unknown,
  refetch: vi.fn(),
  isLoading: false,
}))

vi.mock('../lib/api', () => ({ api: mockApi }))
vi.mock('../hooks/useApi', () => ({
  useApiQuery: () => ({
    data: mockQuery.data,
    refetch: mockQuery.refetch,
    isLoading: mockQuery.isLoading,
  }),
}))
vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

const AUTH = {
  device_code: 'dev-1',
  user_code: 'USER-1',
  client_id: 'client-1',
  scope: 'read',
  status: 'pending',
  created_at: '2026-01-01T10:00:00Z',
  expires_at: '2026-01-01T11:00:00Z',
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = { device_authorizations: [] }
  mockQuery.isLoading = false
  mockApi.post.mockResolvedValue({})
})

describe('DeviceAuthorizationsPage', () => {
  it('shows the loading spinner', () => {
    mockQuery.isLoading = true
    render(<DeviceAuthorizationsPage />)
    expect(screen.queryByText('No device authorizations.')).not.toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(<DeviceAuthorizationsPage />)
    expect(screen.getByText('No device authorizations.')).toBeInTheDocument()
  })

  it('renders rows with a status badge and revoke button', () => {
    mockQuery.data = {
      device_authorizations: [AUTH, { ...AUTH, user_code: 'USER-2', status: 'expired' }],
    }
    render(<DeviceAuthorizationsPage />)
    expect(screen.getByText('USER-1')).toBeInTheDocument()
    expect(screen.getByText('pending')).toBeInTheDocument()
    expect(screen.getByText('expired')).toBeInTheDocument()
    expect(screen.getAllByText('Revoke')).toHaveLength(1)
  })

  it('revokes a device authorization', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQuery.data = { device_authorizations: [AUTH] }
    render(<DeviceAuthorizationsPage />)
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith(
        '/api/oauth2/device/authorizations/USER-1/revoke',
      ),
    )
    expect(notify.success).toHaveBeenCalledWith('Device authorization USER-1 revoked.')
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQuery.data = { device_authorizations: [AUTH] }
    mockApi.post.mockRejectedValueOnce(new Error('boom'))
    render(<DeviceAuthorizationsPage />)
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(notify.error).toHaveBeenCalledWith('Failed to revoke device authorization'),
    )
  })

  it('cancels the revoke dialog', () => {
    mockQuery.data = { device_authorizations: [AUTH] }
    render(<DeviceAuthorizationsPage />)
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()
  })
})