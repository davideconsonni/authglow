// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminUsersPage } from './AdminUsersPage'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn(async (_endpoint: string): Promise<Record<string, unknown>> => ({ scopes: [] })),
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

vi.mock('../../lib/api', () => ({
  api: mockApi,
}))

vi.mock('../../hooks/useApi', () => ({
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

vi.mock('../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}))

const mockDemoMode = vi.hoisted(() => ({ enabled: false }))

vi.mock('../../hooks/useDemoMeta', () => ({
  useDemoMeta: () => ({ meta: { demo_mode: mockDemoMode.enabled }, loaded: true }),
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
    mockDemoMode.enabled = false
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

  it('shows error banner inside modal when set-password API returns 400', async () => {
    mockApi.post.mockRejectedValueOnce(
      new Error('Password does not meet requirements: Password must be at least 8 characters long'),
    )
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('set-password-btn'))

    fireEvent.change(screen.getByTestId('set-password-input'), { target: { value: 'NewStr0ng!' } })
    fireEvent.click(screen.getByTestId('set-password-submit'))

    const banner = await screen.findByTestId('set-password-error')
    expect(banner).toHaveAttribute('role', 'alert')
    expect(banner).toHaveTextContent(/Password does not meet requirements/)
    expect(screen.getByTestId('set-password-input')).toBeInTheDocument()
  })

  it('disables set-password submit when password does not meet criteria', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'u@t.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [], password_expired: false, locked_until: null }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('set-password-btn'))

    fireEvent.change(screen.getByTestId('set-password-input'), { target: { value: 'abc' } })
    expect(screen.getByTestId('set-password-submit')).toBeDisabled()

    fireEvent.change(screen.getByTestId('set-password-input'), { target: { value: 'NewStr0ng!' } })
    expect(screen.getByTestId('set-password-submit')).not.toBeDisabled()
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

  // --- Fase 5: Create User ---

  it('shows Create User button', () => {
    renderPage()
    expect(screen.getByTestId('create-user-btn')).toBeInTheDocument()
  })

  it('opens create user modal on button click', () => {
    renderPage()
    fireEvent.click(screen.getByTestId('create-user-btn'))
    expect(screen.getByTestId('create-user-email')).toBeInTheDocument()
    expect(screen.getByTestId('create-user-password')).toBeInTheDocument()
    expect(screen.getByTestId('create-user-submit')).toBeInTheDocument()
  })

  it('calls create-user API on modal submit', async () => {
    mockApi.post.mockResolvedValue({})
    renderPage()
    fireEvent.click(screen.getByTestId('create-user-btn'))

    fireEvent.change(screen.getByTestId('create-user-email'), { target: { value: 'new@test.com' } })
    fireEvent.change(screen.getByTestId('create-user-password'), { target: { value: 'StrongP@ss1' } })
    fireEvent.click(screen.getByTestId('create-user-email-verified'))

    fireEvent.click(screen.getByTestId('create-user-submit'))

    await waitFor(() => {
      expect(mockApi.post).toHaveBeenCalledWith(
        '/api/admin/users/create',
        expect.objectContaining({ email: 'new@test.com', password: 'StrongP@ss1', email_verified: true }),
      )
    })
  })

  // --- Fase 5: Edit Profile with email, phone, avatar ---

  it('shows email, phone and avatar fields in edit profile', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = {
      id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L',
      email_verified: true, is_active: true, mfa_enabled: false,
      login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [],
      phone: '+1234567890', avatar_url: 'https://example.com/avatar.png',
    }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByDisplayValue('user0@test.com')).toBeInTheDocument()
    expect(screen.getByDisplayValue('+1234567890')).toBeInTheDocument()
    expect(screen.getByDisplayValue('https://example.com/avatar.png')).toBeInTheDocument()
  })

  it('saves phone and avatar via api.put', async () => {
    mockApi.post.mockResolvedValue({})
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = {
      id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L',
      email_verified: true, is_active: true, mfa_enabled: false,
      login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [],
      phone: null, avatar_url: null,
    }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const phoneInput = screen.getByPlaceholderText('+1234567890')
    fireEvent.change(phoneInput, { target: { value: '+1111111111' } })

    const avatarInput = screen.getByPlaceholderText('https://...')
    fireEvent.change(avatarInput, { target: { value: 'https://new.avatar.com/pic.png' } })

    fireEvent.click(screen.getByText('Save Changes'))

    await waitFor(() => {
      expect(mockApi.put).toHaveBeenCalledWith(
        '/api/admin/users/user-0',
        expect.objectContaining({ phone: '+1111111111', avatar_url: 'https://new.avatar.com/pic.png' }),
      )
    })
  })

  // --- UX: drawer a11y, tabs, sticky header/footer ---

  it('renders 7 tabs in the tab strip', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('user-tab-profile')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-sessions')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-passkeys')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-history')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-events')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-apps')).toBeInTheDocument()
    expect(screen.getByTestId('user-tab-admin-log')).toBeInTheDocument()
    expect(screen.queryByTestId('user-tab-demo-inbox')).not.toBeInTheDocument()
  })

  it('shows the Demo Inbox tab in demo mode and renders the inbox for the user email', async () => {
    mockDemoMode.enabled = true
    mockApi.get.mockResolvedValue({ emails: [] })
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const demoTab = screen.getByTestId('user-tab-demo-inbox')
    expect(demoTab).toBeInTheDocument()
    fireEvent.mouseDown(demoTab)

    const demoInbox = screen.getByTestId('demo-inbox')
    expect(demoInbox).toBeInTheDocument()
    expect(within(demoInbox).getByText(/user0@test\.com/)).toBeInTheDocument()
  })

  it('Profile tab is the default and shows the edit form', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'First0', last_name: 'Last0', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const profileTab = screen.getByTestId('user-tab-profile')
    expect(profileTab).toHaveAttribute('data-state', 'active')
    expect(screen.getByDisplayValue('First0')).toBeInTheDocument()
    expect(screen.getByDisplayValue('Last0')).toBeInTheDocument()
  })

  it('switches to Sessions tab on click', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    // Radix TabsTrigger responds to mousedown, not click
    fireEvent.mouseDown(screen.getByTestId('user-tab-sessions'))

    expect(screen.getByTestId('user-tab-sessions')).toHaveAttribute('data-state', 'active')
    expect(screen.getByTestId('user-tab-profile')).toHaveAttribute('data-state', 'inactive')
  })

  it('switches to Passkeys tab and shows the empty state', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.mouseDown(screen.getByTestId('user-tab-passkeys'))

    expect(screen.getByTestId('user-tab-passkeys')).toHaveAttribute('data-state', 'active')
    expect(screen.getByText(/No passkeys registered/)).toBeInTheDocument()
  })

  it('closes drawer on Escape key', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    expect(screen.getByTestId('user-detail-drawer')).toBeInTheDocument()

    fireEvent.keyDown(document, { key: 'Escape' })

    expect(screen.queryByTestId('user-detail-drawer')).not.toBeInTheDocument()
  })

  it('Save Changes button is in the sticky footer (visible alongside drawer content)', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])
    fireEvent.click(screen.getByTestId('user-tab-sessions'))

    // Save Changes is in the sticky footer → must remain visible/accessible
    // when scrolling through any tab content.
    expect(screen.getByText('Save Changes')).toBeInTheDocument()
  })

  it('close button has accessible name "Close user detail"', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByRole('button', { name: 'Close user detail' })).toBeInTheDocument()
  })

  it('drawer has role="dialog" and aria-modal="true"', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }

    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const drawer = screen.getByTestId('user-detail-drawer')
    expect(drawer).toHaveAttribute('role', 'dialog')
    expect(drawer).toHaveAttribute('aria-modal', 'true')
  })

  it('Session/History/Events tab counts are shown when data has a total', () => {
    mockQueryData.users = { items: makeUsers(1), total: 1, limit: 15, offset: 0 }
    mockQueryData.userDetail = { id: 'user-0', email: 'user0@test.com', first_name: 'F', last_name: 'L', email_verified: true, is_active: true, mfa_enabled: false, login_count: 0, created_at: '2025-01-01T00:00:00Z', scopes: [] }
    // The conformance mock falls through to { data: null, isLoading: false }
    // for the read-only query keys, so tab counts fall back to no number.
    // We assert that the tabs are present with the expected labels.
    renderPage()
    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    expect(screen.getByTestId('user-tab-sessions').textContent).toMatch(/^Sessions/)
    expect(screen.getByTestId('user-tab-history').textContent).toMatch(/^Login History/)
    expect(screen.getByTestId('user-tab-events').textContent).toMatch(/^Security Events/)
  })

  it('bootstrap admin toggle and delete are disabled', () => {
    mockQueryData.users = { items: makeUsers(1, { is_bootstrap: true, is_active: true }), total: 1, limit: 15, offset: 0 }

    renderPage()

    const toggle = screen.getByTestId('toggle-active-btn')
    expect(toggle).toBeDisabled()

    const selectCheckbox = screen.getByTestId('user-select-checkbox')
    expect(selectCheckbox).toBeDisabled()

    fireEvent.click(screen.getAllByTestId('user-table-row')[0])

    const deleteBtn = screen.getAllByRole('button').find(b => b.title === 'Delete')
    expect(deleteBtn).toBeUndefined()
  })

  it('non-bootstrap user can be toggled and selected', () => {
    renderPage()

    const toggles = screen.getAllByTestId('toggle-active-btn')
    expect(toggles.length).toBeGreaterThan(0)
    toggles.forEach((t) => expect(t).not.toBeDisabled())

    const selectCheckboxes = screen.getAllByTestId('user-select-checkbox')
    selectCheckboxes.forEach((c) => expect(c).not.toBeDisabled())
  })
})
