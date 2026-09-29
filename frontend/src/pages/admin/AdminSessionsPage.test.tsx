// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdminSessionsPage } from './AdminSessionsPage'

const mockApi = vi.hoisted(() => ({
  post: vi.fn().mockResolvedValue({}),
  get: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))
const mockQuery = vi.hoisted(() => ({
  data: undefined as unknown,
  isLoading: false,
  refetch: vi.fn(),
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({
    data: mockQuery.data,
    refetch: mockQuery.refetch,
    isLoading: mockQuery.isLoading,
  }),
}))
vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../../stores/toastStore', () => ({ notify: { success: vi.fn(), error: vi.fn() } }))

const SESSION = {
  id: 's-1',
  user_email: 'user@example.com',
  client: 'Chrome',
  ip_address: '10.0.0.1',
  scopes: ['read'],
  created_at: '2026-09-01T00:00:00Z',
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = []
  mockQuery.isLoading = false
  mockApi.post.mockResolvedValue({})
})

describe('AdminSessionsPage', () => {
  it('shows the loading spinner', () => {
    mockQuery.isLoading = true
    render(<AdminSessionsPage />)
    expect(screen.queryByText('No active sessions')).not.toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(<AdminSessionsPage />)
    expect(screen.getByText('No active sessions')).toBeInTheDocument()
  })

  it('renders the session rows', () => {
    mockQuery.data = [SESSION]
    render(<AdminSessionsPage />)
    expect(screen.getByText('user@example.com')).toBeInTheDocument()
    expect(screen.getByText('Chrome')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
  })

  it('accepts an object payload with a tokens key', () => {
    mockQuery.data = { tokens: [SESSION] }
    render(<AdminSessionsPage />)
    expect(screen.getByText('Chrome')).toBeInTheDocument()
  })

  it('revokes a session after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = [SESSION]
    render(<AdminSessionsPage />)
    fireEvent.click(screen.getByTitle('Revoke session'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/admin/tokens/refresh/s-1/revoke'),
    )
    expect(notify.success).toHaveBeenCalledWith('Session revoked.')
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = [SESSION]
    mockApi.post.mockRejectedValueOnce(new Error('revoke failed'))
    render(<AdminSessionsPage />)
    fireEvent.click(screen.getByTitle('Revoke session'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke failed'))
  })

  it('cancels the revoke dialog', () => {
    mockQuery.data = [SESSION]
    render(<AdminSessionsPage />)
    fireEvent.click(screen.getByTitle('Revoke session'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('cleans up expired sessions (plural and singular) and toasts failures', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminSessionsPage />)
    mockApi.post.mockResolvedValueOnce({ deleted: 3 })
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Cleaned up 3 expired sessions.'))

    mockApi.post.mockResolvedValueOnce({ deleted: 1 })
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Cleaned up 1 expired session.'))

    mockApi.post.mockRejectedValueOnce(new Error('cleanup down'))
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('cleanup down'))
  })
})
