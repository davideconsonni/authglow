// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AdminDeviceAuthsPage } from './AdminDeviceAuthsPage'

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

function auth(overrides: Record<string, unknown> = {}) {
  return {
    device_code: 'dc-1',
    user_code: 'ABCD-EFGH',
    client_id: 'cli-1',
    scope: 'read write',
    status: 'pending',
    user_id: null,
    created_at: '2026-09-01T00:00:00Z',
    expires_at: '2030-01-01T00:00:00Z',
    authorized_at: null,
    ...overrides,
  }
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AdminDeviceAuthsPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = { device_authorizations: [] }
  mockQuery.isLoading = false
  mockQuery.endpoints = []
  mockApi.post.mockResolvedValue({})
})

describe('AdminDeviceAuthsPage', () => {
  it('shows the loading spinner', () => {
    mockQuery.isLoading = true
    renderPage()
    expect(screen.queryByText(/No device authorization/)).not.toBeInTheDocument()
  })

  it('shows the empty state with a singular/plural count', () => {
    renderPage()
    expect(screen.getByText('No device authorization requests found.')).toBeInTheDocument()
    expect(screen.getByText('0 requests')).toBeInTheDocument()
  })

  it('renders rows, status styles, and conditional revoke controls', () => {
    mockQuery.data = {
      device_authorizations: [
        auth({ device_code: 'dc-1', status: 'pending' }),
        auth({ device_code: 'dc-2', status: 'authorized', user_id: 'u-9' }),
        auth({ device_code: 'dc-3', status: 'denied' }),
        auth({ device_code: 'dc-4', status: 'expired' }),
      ],
    }
    renderPage()
    expect(screen.getByText('4 requests')).toBeInTheDocument()
    // pending + authorized expose the revoke control; denied/expired do not.
    expect(screen.getAllByText('Revoke')).toHaveLength(2)
    expect(screen.getByText('u-9')).toBeInTheDocument()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
    expect(screen.getAllByText('read').length).toBeGreaterThan(0)
  })

  it('uses the singular count for a single request', () => {
    mockQuery.data = { device_authorizations: [auth()] }
    renderPage()
    expect(screen.getByText('1 request')).toBeInTheDocument()
  })

  it('filters by status through the query string', () => {
    renderPage()
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'pending' } })
    expect(mockQuery.endpoints.some((e) => e.includes('?status=pending'))).toBe(true)
  })

  it('revokes a pending authorization after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = { device_authorizations: [auth()] }
    renderPage()
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/admin/device-authorizations/dc-1/revoke'),
    )
    expect(notify.success).toHaveBeenCalledWith('Device authorization ABCD-EFGH revoked.')
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQuery.data = { device_authorizations: [auth()] }
    mockApi.post.mockRejectedValueOnce(new Error('boom'))
    renderPage()
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(notify.error).toHaveBeenCalledWith('Failed to revoke device authorization'),
    )
  })

  it('cancels the revoke dialog', () => {
    mockQuery.data = { device_authorizations: [auth()] }
    renderPage()
    fireEvent.click(screen.getByText('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()
  })
})
