// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SessionsPage } from './SessionsPage'

const mockApi = vi.hoisted(() => ({ post: vi.fn(), delete: vi.fn() }))
const mockQuery = vi.hoisted(() => ({
  sessions: undefined as unknown,
  myToken: undefined as unknown,
  isLoading: false,
  refetch: vi.fn(),
}))

vi.mock('../lib/api', () => ({ api: mockApi }))
vi.mock('../hooks/useApi', () => ({
  useApiQuery: (_key: string[], endpoint: string) => {
    if (endpoint === '/api/tokens/refresh/list') {
      return { data: mockQuery.sessions, refetch: mockQuery.refetch, isLoading: mockQuery.isLoading }
    }
    if (endpoint === '/api/auth/my-token') {
      return { data: mockQuery.myToken, refetch: vi.fn(), isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))
vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

const SESSIONS = [
  { id: 's1', client: 'Chrome', ip_address: '10.0.0.1', created_at: '2026-08-25T08:00:00Z', last_active: '2026-08-25T09:00:00Z' },
  { id: 's2', client: 'Firefox', ip_address: '10.0.0.2', created_at: '2026-08-25T08:00:00Z', last_active: '2026-08-25T16:00:00Z' },
]

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.sessions = SESSIONS
  mockQuery.myToken = undefined
  mockQuery.isLoading = false
  mockApi.post.mockResolvedValue({})
  mockApi.delete.mockResolvedValue({})
})

describe('SessionsPage — sessions list and revoke', () => {
  it('shows the loading state', () => {
    mockQuery.isLoading = true
    render(<SessionsPage />)
    expect(screen.getByText('Loading sessions...')).toBeInTheDocument()
  })

  it('shows the empty state', () => {
    mockQuery.sessions = []
    render(<SessionsPage />)
    expect(screen.getByText('No active sessions')).toBeInTheDocument()
  })

  it('marks the most recently active session as this device', () => {
    render(<SessionsPage />)
    expect(screen.getAllByText('This device').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Firefox').length).toBeGreaterThan(0)
  })

  it('accepts a { sessions } payload', () => {
    mockQuery.sessions = { sessions: SESSIONS }
    render(<SessionsPage />)
    expect(screen.getAllByText('Chrome').length).toBeGreaterThan(0)
  })

  it('revokes all sessions with a plural count', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.post.mockResolvedValueOnce({ count: 2 })
    render(<SessionsPage />)
    fireEvent.click(screen.getByText('Revoke all'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Revoked 2 sessions.'))
  })

  it('revokes all sessions with a singular count', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.post.mockResolvedValueOnce({ count: 1 })
    render(<SessionsPage />)
    fireEvent.click(screen.getByText('Revoke all'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Revoked 1 session.'))
  })

  it('reports a zero-count revoke-all', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.post.mockResolvedValueOnce({ count: 0 })
    render(<SessionsPage />)
    fireEvent.click(screen.getByText('Revoke all'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('All sessions revoked.'))
  })

  it('toasts a revoke-all failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.post.mockRejectedValueOnce(new Error('revoke-all failed'))
    render(<SessionsPage />)
    fireEvent.click(screen.getByText('Revoke all'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke-all failed'))
  })

  it('revokes a single session after confirmation', async () => {
    const { notify } = await import('../stores/toastStore')
    render(<SessionsPage />)
    fireEvent.click(screen.getAllByLabelText('Revoke session')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalledWith('/api/tokens/refresh/s1'))
    expect(notify.success).toHaveBeenCalledWith('Session revoked.')
  })

  it('toasts a single-session revoke failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.delete.mockRejectedValueOnce(new Error('revoke failed'))
    render(<SessionsPage />)
    fireEvent.click(screen.getAllByLabelText('Revoke session')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke failed'))
  })

  it('cancels the revoke dialog', () => {
    render(<SessionsPage />)
    fireEvent.click(screen.getAllByLabelText('Revoke session')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })
})
