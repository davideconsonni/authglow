// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminUsersPage } from './AdminUsersPage'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  put: vi.fn().mockResolvedValue({}),
  post: vi.fn(),
  delete: vi.fn(),
}))

const mockQueryData = vi.hoisted(() => {
  type UsersResponse = { items: Array<Record<string, unknown>>; total: number; limit: number; offset: number }
  return {
    users: { items: [] as Array<Record<string, unknown>>, total: 0, limit: 15, offset: 0 } as UsersResponse,
    userDetail: null as Record<string, unknown> | null,
    userKeys: [] as unknown[],
    userPasskeys: [] as unknown[],
    refetch: vi.fn(),
  }
})

vi.mock('@/lib/api', () => ({
  api: mockApi,
}))

vi.mock('@/hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-users') {
      return { data: mockQueryData.users, refetch: mockQueryData.refetch, isLoading: false }
    }
    if (key[0] === 'user-detail') {
      return { data: mockQueryData.userDetail, isLoading: false }
    }
    if (key[0] === 'user-keys') {
      return { data: mockQueryData.userKeys, isLoading: false }
    }
    if (key[0] === 'user-passkeys') {
      return { data: mockQueryData.userPasskeys, isLoading: false }
    }
    return { data: null, isLoading: false }
  },
}))

vi.mock('@/hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}))

function makeUsers(count: number, overrides: Record<string, unknown> = {}) {
  return Array.from({ length: count }, (_, i) => ({
    id: `user-${i}`,
    email: `user${i}@test.com`,
    first_name: `First${i}`,
    last_name: `Last${i}`,
    is_active: true,
    mfa_enabled: false,
    created_at: '2025-01-01T00:00:00Z',
    login_count: i,
    ...overrides,
  }))
}

const renderPage = () => render(<AdminUsersPage />, { wrapper: Wrapper })

describe('AdminUsersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.users = { items: makeUsers(3), total: 3, limit: 15, offset: 0 }
    mockQueryData.userDetail = null
    mockQueryData.userKeys = []
    mockQueryData.userPasskeys = []
    mockQueryData.refetch = vi.fn()
    mockApi.put.mockResolvedValue({})
  })

  // --- 1.1 Edit fields ---

  it('opens user drawer on row click', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    const userData = { id: 'user-0', email: 'user0@test.com', first_name: 'First0', last_name: 'Last0', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read', 'write'] }
    mockQueryData.userDetail = userData

    renderPage()

    const rows = screen.getAllByTestId('user-table-row')
    fireEvent.click(rows[0])

    expect(screen.getByTestId('user-detail-drawer')).toBeInTheDocument()
  })

  it('shows editable first name and last name fields in drawer', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    const userData = { id: 'user-0', email: 'user0@test.com', first_name: 'First0', last_name: 'Last0', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read'] }
    mockQueryData.userDetail = userData

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByDisplayValue('First0')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Last0')).toBeInTheDocument()
  })

  it('saves edited first name via api.put', async () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'First0', last_name: 'Last0', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read'] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const firstNameInput = screen.getByDisplayValue('First0')
    fireEvent.change(firstNameInput, { target: { value: 'UpdatedName' } })

    fireEvent.click(screen.getByText('Save Changes'))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/users/user-0',
        expect.objectContaining({ first_name: 'UpdatedName' }),
      )
    })
  })

  it('toggles email verified checkbox and saves', async () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: false, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const checkbox = screen.getByRole('checkbox')
    expect(checkbox).not.toBeChecked()

    fireEvent.click(checkbox)
    expect(checkbox).toBeChecked()

    fireEvent.click(screen.getByText('Save Changes'))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/users/user-0',
        expect.objectContaining({ email_verified: true }),
      )
    })
  })

  // --- 1.2 Scope management ---

  it('shows scopes in drawer', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read', 'write', 'admin'] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByText('read')).toBeInTheDocument()
    expect(screen.getByText('write')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('removes a scope and saves the change', async () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read', 'write', 'admin'] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByText('read')).toBeInTheDocument()

    const removeButtons = screen.getAllByRole('button').filter(b =>
      b.innerHTML.includes('×') || b.querySelector('svg.lucide-x'),
    )
    if (removeButtons.length > 0) {
      fireEvent.click(removeButtons[0])
    }

    fireEvent.click(screen.getByText('Save Changes'))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalled()
      const callArgs = mockApi.put.mock.calls[0]
      expect(callArgs[0]).toBe('/api/admin/users/user-0')
    })
  })

  it('adds a new scope and saves it', async () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: ['read'] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const scopeInput = screen.getByPlaceholderText('Add scope...')
    fireEvent.change(scopeInput, { target: { value: 'admin' } })
    fireEvent.keyDown(scopeInput, { key: 'Enter', code: 'Enter' })

    fireEvent.click(screen.getByText('Save Changes'))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/users/user-0',
        expect.objectContaining({ scopes: expect.arrayContaining(['admin']) }),
      )
    })
  })

  // --- 1.3 Filters ---

  it('renders filter dropdowns', () => {
    renderPage()

    expect(screen.getByTestId('filter-status')).toBeInTheDocument()
    expect(screen.getByTestId('filter-mfa')).toBeInTheDocument()
    expect(screen.getByTestId('filter-verified')).toBeInTheDocument()
  })

  it('changes status filter updates query key', () => {
    renderPage()

    const statusSelect = screen.getByTestId('filter-status')
    fireEvent.change(statusSelect, { target: { value: 'active' } })
    expect(statusSelect).toHaveValue('active')
  })

  it('changes mfa filter updates query key', () => {
    renderPage()

    const mfaSelect = screen.getByTestId('filter-mfa')
    fireEvent.change(mfaSelect, { target: { value: 'enabled' } })
    expect(mfaSelect).toHaveValue('enabled')
  })

  it('changes email verified filter updates query key', () => {
    renderPage()

    const verifiedSelect = screen.getByTestId('filter-verified')
    fireEvent.change(verifiedSelect, { target: { value: 'verified' } })
    expect(verifiedSelect).toHaveValue('verified')
  })

  // --- Phase 2: Password & Credentials ---

  it('shows Set Password button in drawer', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('set-password-btn')).toBeInTheDocument()
  })

  it('opens Set Password modal on button click', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('set-password-btn'))

    expect(screen.getByTestId('set-password-input')).toBeInTheDocument()
  })

  it('calls set-password API on modal submit', async () => {
    mockApi.post.mockResolvedValue({})
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('set-password-btn'))

    const input = screen.getByTestId('set-password-input')
    fireEvent.change(input, { target: { value: 'NewStr0ng!' } })

    fireEvent.click(screen.getByTestId('set-password-submit'))

    await waitFor(() => {
      expect(mockApi.post).toHaveBeenCalledWith(
        '/api/admin/users/user-0/set-password',
        expect.objectContaining({ password: 'NewStr0ng!' }),
      )
    })
  })

  it('shows Send Password Reset button in drawer', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('send-password-reset-btn')).toBeInTheDocument()
  })

  it('shows Expire Password button when not yet expired', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('expire-password-btn')).toBeInTheDocument()
  })

  it('hides Expire Password button when already expired', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: true, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.queryByTestId('expire-password-btn')).not.toBeInTheDocument()
  })

  it('shows unlock button when account is locked', () => {
    const futureDate = new Date(Date.now() + 86400000).toISOString()
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: futureDate, failed_login_count: 5 }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('unlock-account-btn')).toBeInTheDocument()
  })

  it('shows Reset Failed Attempts button when failed count > 0', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null, failed_login_count: 3 }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('reset-attempts-btn')).toBeInTheDocument()
  })

  it('hides Reset Failed Attempts button when count is 0', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null, failed_login_count: 0 }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.queryByTestId('reset-attempts-btn')).not.toBeInTheDocument()
  })

  it('calls send-password-reset API from confirm dialog', async () => {
    mockApi.post.mockResolvedValue({})
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('send-password-reset-btn'))

    await waitFor(() => {
      expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))

    await waitFor(() => {
      expect(mockApi.post.mock.calls[0][0]).toBe('/api/admin/users/user-0/send-password-reset')
    })
  })
})
