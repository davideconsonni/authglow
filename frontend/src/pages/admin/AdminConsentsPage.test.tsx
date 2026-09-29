// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdminConsentsPage } from './AdminConsentsPage'

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
  endpoints: [] as string[],
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (_key: string[], endpoint: string) => {
    mockQuery.endpoints.push(endpoint)
    return { data: mockQuery.data, refetch: mockQuery.refetch, isLoading: mockQuery.isLoading }
  },
}))
vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../../stores/toastStore', () => ({ notify: { success: vi.fn(), error: vi.fn() } }))

const CONSENT = {
  consent_id: 'c-1',
  user_email: 'user@example.com',
  client_name: 'Third Party',
  scopes: ['read', 'write'],
  granted_at: '2026-01-01T00:00:00Z',
  revoked: false,
  revoked_at: null,
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = []
  mockQuery.isLoading = false
  mockQuery.endpoints = []
  mockApi.post.mockResolvedValue({})
})

describe('AdminConsentsPage', () => {
  it('shows the loading spinner', () => {
    mockQuery.isLoading = true
    render(<AdminConsentsPage />)
    expect(screen.queryByText('No consents')).not.toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(<AdminConsentsPage />)
    expect(screen.getByText('No consents')).toBeInTheDocument()
    expect(screen.getByText(/consent grants will appear here/i)).toBeInTheDocument()
  })

  it('shows the filtered empty state when searching', () => {
    render(<AdminConsentsPage />)
    fireEvent.change(screen.getByPlaceholderText('Filter by user email...'), {
      target: { value: 'nobody@example.com' },
    })
    expect(screen.getByText('No consents match your filter.')).toBeInTheDocument()
    expect(mockQuery.endpoints.some((e) => e.includes('?email=nobody%40example.com'))).toBe(true)
  })

  it('renders the consent rows from an array payload', () => {
    mockQuery.data = [CONSENT, { ...CONSENT, consent_id: 'c-2', revoked: true }]
    render(<AdminConsentsPage />)
    expect(screen.getAllByText('user@example.com')).toHaveLength(2)
    expect(screen.getAllByText('Third Party')).toHaveLength(2)
    // Only the non-revoked consent exposes the revoke control.
    expect(screen.getAllByTitle('Revoke consent')).toHaveLength(1)
  })

  it('accepts an object payload with an items key', () => {
    mockQuery.data = { consents: [CONSENT] }
    render(<AdminConsentsPage />)
    expect(screen.getByText('Third Party')).toBeInTheDocument()
  })

  it('revokes a consent after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = [CONSENT]
    render(<AdminConsentsPage />)
    fireEvent.click(screen.getByTitle('Revoke consent'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/admin/oauth-consents/c-1/revoke'),
    )
    expect(notify.success).toHaveBeenCalledWith('Consent revoked.')
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('cancels the revoke dialog', () => {
    mockQuery.data = [CONSENT]
    render(<AdminConsentsPage />)
    fireEvent.click(screen.getByTitle('Revoke consent'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = [CONSENT]
    mockApi.post.mockRejectedValueOnce(new Error('nope'))
    render(<AdminConsentsPage />)
    fireEvent.click(screen.getByTitle('Revoke consent'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('nope'))
  })
})
