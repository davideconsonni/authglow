// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdminRbacPage } from './AdminRbacPage'

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({ items: [] }),
  post: vi.fn().mockResolvedValue({}),
  patch: vi.fn().mockResolvedValue({}),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockData = vi.hoisted(() => ({
  roles: [] as Array<Record<string, unknown>>,
  permissions: [] as Array<Record<string, unknown>>,
  userRoles: [] as Array<Record<string, unknown>>,
  rolesLoading: false,
  permsLoading: false,
  userRolesLoading: false,
  refetchRoles: vi.fn(),
  refetchPerms: vi.fn(),
  refetchUserRoles: vi.fn(),
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-roles') {
      return { data: mockData.roles, refetch: mockData.refetchRoles, isLoading: mockData.rolesLoading }
    }
    if (key[0] === 'admin-permissions') {
      return {
        data: mockData.permissions,
        refetch: mockData.refetchPerms,
        isLoading: mockData.permsLoading,
      }
    }
    if (key[0] === 'user-roles') {
      return {
        data: mockData.userRoles,
        refetch: mockData.refetchUserRoles,
        isLoading: mockData.userRolesLoading,
      }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

const SYSTEM_ROLE = {
  role_id: 'sys-1',
  name: 'Authglow Administrator',
  description: 'built-in',
  permissions: ['users.read', 'users.write'],
  is_system: true,
}
const CUSTOM_ROLE = {
  role_id: 'r-1',
  name: 'Support',
  description: 'support staff',
  permissions: [],
  is_system: false,
}

beforeEach(() => {
  vi.clearAllMocks()
  mockData.roles = []
  mockData.permissions = []
  mockData.userRoles = []
  mockData.rolesLoading = false
  mockData.permsLoading = false
  mockData.userRolesLoading = false
  mockApi.get.mockResolvedValue({ items: [] })
})

describe('AdminRbacPage — tabs', () => {
  it('defaults to roles and switches to permissions', () => {
    render(<AdminRbacPage />)
    expect(screen.getAllByText('Create Role').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByText('permissions'))
    expect(screen.getAllByText('Create Permission').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Create Role')).toHaveLength(0)
  })
})

describe('AdminRbacPage — roles tab', () => {
  it('shows the loading spinner', () => {
    mockData.rolesLoading = true
    mockData.roles = [CUSTOM_ROLE]
    render(<AdminRbacPage />)
    expect(screen.queryByText('No roles')).not.toBeInTheDocument()
    expect(screen.queryByText('Support')).not.toBeInTheDocument()
  })

  it('shows the empty state', () => {
    render(<AdminRbacPage />)
    expect(screen.getByText('No roles')).toBeInTheDocument()
    fireEvent.click(screen.getAllByText('Create Role')[1])
    expect(screen.getByPlaceholderText('admin')).toBeInTheDocument()
  })

  it('renders system and custom roles with their permissions', () => {
    mockData.roles = [SYSTEM_ROLE, CUSTOM_ROLE]
    render(<AdminRbacPage />)
    expect(screen.getByText('Authglow Administrator')).toBeInTheDocument()
    expect(screen.getByText('SYSTEM')).toBeInTheDocument()
    expect(screen.getByText('Support')).toBeInTheDocument()
    expect(screen.getByText('None')).toBeInTheDocument()
    // System roles expose no edit/delete controls.
    expect(screen.getAllByTitle('Edit role')).toHaveLength(1)
    expect(screen.getAllByTitle('Delete role')).toHaveLength(1)
  })

  it('creates a role with selected permissions', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.permissions = [
      { permission_id: 'p-1', name: 'users.read', description: 'read users' },
      { permission_id: 'p-2', name: 'users.write', description: '' },
    ]
    render(<AdminRbacPage />)
    fireEvent.click(screen.getAllByText('Create Role')[0])
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'Support' } })
    fireEvent.change(screen.getByPlaceholderText('Administrator role'), {
      target: { value: 'support staff' },
    })
    const checkboxes = screen.getAllByRole('checkbox')
    fireEvent.click(checkboxes[0])
    fireEvent.click(checkboxes[0]) // toggle off again
    fireEvent.click(checkboxes[1])
    fireEvent.click(screen.getByText('Save'))

    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/rbac/roles', {
        name: 'Support',
        description: 'support staff',
        permissions: ['users.write'],
      }),
    )
    expect(notify.success).toHaveBeenCalledWith('Role created.')
    expect(mockData.refetchRoles).toHaveBeenCalled()
  })

  it('keeps Save disabled until a name is entered', () => {
    render(<AdminRbacPage />)
    fireEvent.click(screen.getAllByText('Create Role')[0])
    const save = screen.getByText('Save').closest('button') as HTMLButtonElement
    expect(save.disabled).toBe(true)
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'X' } })
    expect(save.disabled).toBe(false)
  })

  it('toasts a create failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.post.mockRejectedValueOnce(new Error('nope'))
    render(<AdminRbacPage />)
    fireEvent.click(screen.getAllByText('Create Role')[0])
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'X' } })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('nope'))
  })

  it('edits an existing role', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.roles = [CUSTOM_ROLE]
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByTitle('Edit role'))
    expect(screen.getByText('Edit Role')).toBeInTheDocument()
    expect((screen.getByPlaceholderText('admin') as HTMLInputElement).value).toBe('Support')
    fireEvent.change(screen.getByPlaceholderText('admin'), { target: { value: 'Support II' } })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith('/api/rbac/roles/r-1', {
        name: 'Support II',
        description: 'support staff',
        permissions: [],
      }),
    )
    expect(notify.success).toHaveBeenCalledWith('Role updated.')
  })

  it('deletes a role after confirmation and supports cancel', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.roles = [CUSTOM_ROLE]
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByTitle('Delete role'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()

    fireEvent.click(screen.getByTitle('Delete role'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalledWith('/api/rbac/roles/r-1'))
    expect(notify.success).toHaveBeenCalledWith('Role deleted.')
  })

  it('toasts a delete failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.roles = [CUSTOM_ROLE]
    mockApi.delete.mockRejectedValueOnce(new Error('cant delete'))
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByTitle('Delete role'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('cant delete'))
  })

  it('closes the create modal via Cancel and via backdrop', () => {
    render(<AdminRbacPage />)
    fireEvent.click(screen.getAllByText('Create Role')[0])
    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByPlaceholderText('admin')).not.toBeInTheDocument()

    fireEvent.click(screen.getAllByText('Create Role')[0])
    const backdrop = document.querySelector('.absolute.inset-0') as HTMLElement
    fireEvent.click(backdrop)
    expect(screen.queryByPlaceholderText('admin')).not.toBeInTheDocument()
  })
})

describe('AdminRbacPage — permissions tab', () => {
  beforeEach(() => {
    mockData.permissions = [
      { permission_id: 'p-1', name: 'users.read', description: 'read users' },
    ]
  })

  it('shows the empty state when there are no permissions', () => {
    mockData.permissions = []
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    expect(screen.getByText('No permissions')).toBeInTheDocument()
    fireEvent.click(screen.getAllByText('Create Permission')[1])
    expect(screen.getByPlaceholderText('users.read')).toBeInTheDocument()
  })

  it('lists permissions and creates a new one', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    expect(screen.getByText('users.read')).toBeInTheDocument()

    fireEvent.click(screen.getByText('Create Permission'))
    fireEvent.change(screen.getByPlaceholderText('users.read'), { target: { value: 'users.delete' } })
    fireEvent.change(screen.getByPlaceholderText('View user profiles'), {
      target: { value: 'delete users' },
    })
    fireEvent.click(screen.getByText('Create'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/rbac/permissions', {
        name: 'users.delete',
        description: 'delete users',
      }),
    )
    expect(notify.success).toHaveBeenCalledWith('Permission created.')
  })

  it('toasts a permission create failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.post.mockRejectedValueOnce(new Error('bad perm'))
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByText('Create Permission'))
    fireEvent.change(screen.getByPlaceholderText('users.read'), { target: { value: 'x' } })
    fireEvent.click(screen.getByText('Create'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('bad perm'))
  })

  it('deletes a permission after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByTitle('Delete permission'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.delete).toHaveBeenCalledWith('/api/rbac/permissions/p-1'),
    )
    expect(notify.success).toHaveBeenCalledWith('Permission deleted.')
  })

  it('toasts a permission delete failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.delete.mockRejectedValueOnce(new Error('locked'))
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByTitle('Delete permission'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('locked'))
  })

  it('closes the create-permission modal via backdrop', () => {
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByText('Create Permission'))
    const backdrop = document.querySelector('.absolute.inset-0') as HTMLElement
    fireEvent.click(backdrop)
    expect(screen.queryByPlaceholderText('users.read')).not.toBeInTheDocument()
  })

  it('closes the create-permission modal via Cancel', () => {
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByText('Create Permission'))
    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByPlaceholderText('users.read')).not.toBeInTheDocument()
  })

  it('cancels the delete-permission dialog', () => {
    render(<AdminRbacPage />)
    fireEvent.click(screen.getByText('permissions'))
    fireEvent.click(screen.getByTitle('Delete permission'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })
})

describe('AdminRbacPage — user role assignments', () => {
  it('does not submit a search for an empty email', () => {
    render(<AdminRbacPage />)
    const input = screen.getByPlaceholderText('user@example.com')
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(mockApi.get).not.toHaveBeenCalled()
  })

  it('toasts when the user is not found', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.get.mockResolvedValueOnce({ items: [] })
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'ghost@example.com' },
    })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('User not found'))
  })

  it('toasts a search failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.get.mockRejectedValueOnce(new Error('search down'))
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'x@example.com' },
    })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('search down'))
  })

  it('searches, assigns a role, and revokes an assignment', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.roles = [CUSTOM_ROLE]
    mockData.userRoles = [
      { role_id: 'r-1', user_email: 'user@example.com', role_name: 'Support', expires_at: null },
    ]
    render(<AdminRbacPage />)

    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    mockApi.get.mockResolvedValueOnce({ items: [{ id: 'u-1' }] })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(screen.getByText('Assign role')).toBeInTheDocument())
    expect(screen.getByText('Never')).toBeInTheDocument()

    // Assign: role select + optional expiry.
    const select = screen.getByRole('combobox')
    fireEvent.change(select, { target: { value: 'r-1' } })
    const dateInput = document.querySelector('input[type="date"]') as HTMLInputElement
    fireEvent.change(dateInput, { target: { value: '2030-01-01' } })
    fireEvent.click(screen.getByText('Assign'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/rbac/user-roles', {
        user_id: 'u-1',
        role_id: 'r-1',
        expires_at: '2030-01-01',
      }),
    )
    expect(notify.success).toHaveBeenCalledWith('Role assigned.')

    fireEvent.click(screen.getByTitle('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.delete).toHaveBeenCalledWith('/api/rbac/user-roles/u-1/r-1'),
    )
    expect(notify.success).toHaveBeenCalledWith('Assignment revoked.')
  })

  it('shows the empty assignments state after a search', async () => {
    mockData.userRoles = []
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    mockApi.get.mockResolvedValueOnce({ items: [{ id: 'u-1' }] })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() =>
      expect(screen.getByText('No roles assigned to this user.')).toBeInTheDocument(),
    )
  })

  it('toasts an assign failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.roles = [CUSTOM_ROLE]
    mockApi.post.mockRejectedValueOnce(new Error('assign boom'))
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    mockApi.get.mockResolvedValueOnce({ items: [{ id: 'u-1' }] })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(screen.getByRole('combobox')).toBeInTheDocument())
    fireEvent.change(screen.getByRole('combobox'), { target: { value: 'r-1' } })
    fireEvent.click(screen.getByText('Assign'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('assign boom'))
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockData.userRoles = [{ role_id: 'r-1', user_email: 'user@example.com' }]
    mockApi.delete.mockRejectedValueOnce(new Error('revoke boom'))
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    mockApi.get.mockResolvedValueOnce({ items: [{ id: 'u-1' }] })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(screen.getByTitle('Revoke')).toBeInTheDocument())
    fireEvent.click(screen.getByTitle('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke boom'))
  })

  it('cancels the revoke dialog', async () => {
    mockData.userRoles = [{ role_id: 'r-1', user_email: 'user@example.com' }]
    render(<AdminRbacPage />)
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    mockApi.get.mockResolvedValueOnce({ items: [{ id: 'u-1' }] })
    fireEvent.click(screen.getByText('Search'))
    await waitFor(() => expect(screen.getByTitle('Revoke')).toBeInTheDocument())
    fireEvent.click(screen.getByTitle('Revoke'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })
})
