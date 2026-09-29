// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdminPasswordResetsPage } from './AdminPasswordResetsPage'

const mockApi = vi.hoisted(() => ({
  post: vi.fn().mockResolvedValue({}),
  get: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn().mockResolvedValue({}),
}))
const mockData = vi.hoisted(() => ({
  tokens: undefined as unknown,
  stats: undefined as Record<string, number> | undefined,
  loading: false,
  refetch: vi.fn(),
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-reset-stats') return { data: mockData.stats }
    return { data: mockData.tokens, refetch: mockData.refetch, isLoading: mockData.loading }
  },
}))
vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../../stores/toastStore', () => ({ notify: { success: vi.fn(), error: vi.fn() } }))

function token(overrides: Record<string, unknown> = {}) {
  return {
    token_id: 't-1',
    email: 'user@example.com',
    reset_code: 'ABCD1234EFGH',
    token_lookup: 'lookup-hash',
    token_hash: 'hash',
    is_used: false,
    created_at: '2026-09-01T00:00:00Z',
    expires_at: '2030-01-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockData.tokens = []
  mockData.stats = undefined
  mockData.loading = false
  mockApi.post.mockResolvedValue({})
  mockApi.delete.mockResolvedValue({})
})

describe('AdminPasswordResetsPage', () => {
  it('shows the loading spinner', () => {
    mockData.loading = true
    render(<AdminPasswordResetsPage />)
    expect(screen.queryByText('No password reset requests')).not.toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(<AdminPasswordResetsPage />)
    expect(screen.getByText('No password reset requests')).toBeInTheDocument()
  })

  it('renders stats and the three token statuses', () => {
    mockData.stats = { total: 5, pending: 2, completed: 2, expired: 1 }
    mockData.tokens = [
      token({ token_id: 't-active' }),
      token({ token_id: 't-used', is_used: true }),
      token({ token_id: 't-expired', expires_at: '2000-01-01T00:00:00Z' }),
    ]
    render(<AdminPasswordResetsPage />)
    expect(screen.getByText('Total')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Used')).toBeInTheDocument()
    expect(screen.getAllByText('Expired').length).toBeGreaterThan(0)
  })

  it('accepts an object payload with a tokens key', () => {
    mockData.tokens = { items: [token()] }
    render(<AdminPasswordResetsPage />)
    expect(screen.getByText('user@example.com')).toBeInTheDocument()
  })

  it('deletes a token after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.tokens = [token()]
    render(<AdminPasswordResetsPage />)
    fireEvent.click(screen.getByTitle('Delete token'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.delete).toHaveBeenCalledWith('/api/admin/password-resets/t-1'),
    )
    expect(notify.success).toHaveBeenCalledWith('Token deleted.')
  })

  it('cancels the delete dialog', () => {
    mockData.tokens = [token()]
    render(<AdminPasswordResetsPage />)
    fireEvent.click(screen.getByTitle('Delete token'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })

  it('toasts a delete failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.tokens = [token()]
    mockApi.delete.mockRejectedValueOnce(new Error('nope'))
    render(<AdminPasswordResetsPage />)
    fireEvent.click(screen.getByTitle('Delete token'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('nope'))
  })

  it('revokes all tokens for a user by email', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.post.mockResolvedValueOnce({ message: 'All reset tokens revoked' })
    render(<AdminPasswordResetsPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'victim@example.com' },
    })
    fireEvent.click(screen.getByText('Revoke'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith(
        '/api/admin/users/victim@example.com/revoke-resets',
      ),
    )
    expect(notify.success).toHaveBeenCalledWith('All reset tokens revoked')
  })

  it('falls back to a default message and toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.tokens = []
    render(<AdminPasswordResetsPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'victim@example.com' },
    })
    fireEvent.click(screen.getByText('Revoke'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith(
      'Reset tokens revoked for victim@example.com',
    ))

    mockApi.post.mockRejectedValueOnce(new Error('gone'))
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'someone@example.com' },
    })
    fireEvent.click(screen.getByText('Revoke'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('gone'))
  })

  it('cleans up expired tokens and toasts failures', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminPasswordResetsPage />)
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Expired tokens cleaned up.'))

    mockApi.post.mockRejectedValueOnce(new Error('cleanup failed'))
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('cleanup failed'))
  })
})
