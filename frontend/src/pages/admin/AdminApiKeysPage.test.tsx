// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { AdminApiKeysPage } from './AdminApiKeysPage'

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({ scopes: ['read', 'write'] }),
  post: vi.fn().mockResolvedValue({}),
  patch: vi.fn().mockResolvedValue({}),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  data: undefined as unknown,
  refetch: vi.fn(),
  isLoading: false,
  invalidateApiKeyLists: vi.fn(),
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({
    data: mockQueryData.data,
    refetch: mockQueryData.refetch,
    isLoading: mockQueryData.isLoading,
  }),
  useApiKeyInvalidation: () => ({ invalidateApiKeyLists: mockQueryData.invalidateApiKeyLists }),
}))

vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

// Lightweight stand-in: the real dialog owns its own multi-phase safeword
// flow (out of scope here). The stub exposes the callbacks the page wires.
vi.mock('../../components/admin/RotateSecretDialog', () => ({
  RotateSecretDialog: ({
    open,
    purpose,
    targetLabel,
    onClose,
    onSuccess,
    onError,
  }: {
    open: boolean
    purpose: string
    targetLabel?: string
    onClose: () => void
    onSuccess: (credential?: string) => void | Promise<void>
    onError: (message: string) => void
  }) =>
    open ? (
      <div data-testid={`rsd-${purpose}`}>
        <span data-testid={`rsd-${purpose}-label`}>{targetLabel}</span>
        <button data-testid={`rsd-${purpose}-close`} onClick={onClose}>
          close
        </button>
        <button
          data-testid={`rsd-${purpose}-success`}
          onClick={() => {
            void onSuccess(purpose === 'api_key_rotate' ? 'NEW-SECRET' : undefined)
          }}
        >
          success
        </button>
        <button data-testid={`rsd-${purpose}-error`} onClick={() => onError('boom')}>
          error
        </button>
      </div>
    ) : null,
}))

// Stub the claims modal: it owns its own API surface and is covered elsewhere.
vi.mock('../../components/admin/ApiKeyClaimsTab', () => ({
  ApiKeyClaimsTab: ({ keyName, onClose }: { keyName: string; onClose: () => void }) => (
    <div data-testid="claims-tab">
      <span>{keyName}</span>
      <button onClick={onClose}>close-claims</button>
    </div>
  ),
}))

function makeKey(overrides: Record<string, unknown> = {}) {
  return {
    key_id: 'k1',
    user_id: 'u1',
    user_email: 'user@example.com',
    name: 'Alpha',
    description: 'desc',
    key_prefix: 'ak_abc',
    scopes: ['read', 'write'],
    created_at: '2025-01-01T00:00:00Z',
    is_active: true,
    expires_at: '2030-01-01T00:00:00Z',
    never_expires: false,
    allowed_ips: ['1.2.3.4', '5.6.7.8'],
    ...overrides,
  }
}

function openCreate() {
  fireEvent.click(screen.getAllByText('Create Key')[0])
}

function submitCreate() {
  const card = screen.getByText('Create API Key').closest('div') as HTMLElement
  fireEvent.click(within(card).getByText('Create Key'))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQueryData.data = []
  mockQueryData.isLoading = false
  mockApi.get.mockResolvedValue({ scopes: ['read', 'write'] })
  mockApi.post.mockResolvedValue({})
  mockApi.patch.mockResolvedValue({})
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn() },
    configurable: true,
  })
})

describe('AdminApiKeysPage — render', () => {
  it('shows the loading spinner', () => {
    mockQueryData.isLoading = true
    render(<AdminApiKeysPage />)
    expect(screen.queryByText('No API keys')).not.toBeInTheDocument()
  })

  it('shows the empty state without a filter', () => {
    render(<AdminApiKeysPage />)
    expect(screen.getByText('No API keys')).toBeInTheDocument()
    expect(screen.getByText('Create your first API key to get started.')).toBeInTheDocument()
  })

  it('shows the filtered empty state when searching', () => {
    render(<AdminApiKeysPage />)
    fireEvent.change(screen.getByPlaceholderText('Filter by user email...'), {
      target: { value: 'nobody' },
    })
    expect(screen.getByText('No keys match your filter. Try different keywords.')).toBeInTheDocument()
  })

  it('accepts a { items } payload', () => {
    mockQueryData.data = { items: [makeKey()] }
    render(<AdminApiKeysPage />)
    expect(screen.getByText('Alpha')).toBeInTheDocument()
  })

  it('accepts a { keys } payload', () => {
    mockQueryData.data = { keys: [makeKey({ key_id: 'k9', name: 'Beta' })] }
    render(<AdminApiKeysPage />)
    expect(screen.getByText('Beta')).toBeInTheDocument()
  })

  it('falls back to an empty list for an unknown payload shape', () => {
    mockQueryData.data = {}
    render(<AdminApiKeysPage />)
    expect(screen.getByText('No API keys')).toBeInTheDocument()
  })

  it('renders rows with user, scopes, IP restriction and expiry', () => {
    mockQueryData.data = [
      makeKey(),
      makeKey({
        key_id: 'k2',
        name: 'Beta',
        description: null,
        scopes: ['read'],
        is_active: false,
        expires_at: null,
        allowed_ips: [],
      }),
    ]
    render(<AdminApiKeysPage />)
    expect(screen.getAllByText('user@example.com')).toHaveLength(2)
    expect(screen.getByText('Alpha')).toBeInTheDocument()
    expect(screen.getByText('Beta')).toBeInTheDocument()
    expect(screen.queryByTestId('key-description-display')).toBeInTheDocument()
    const ips = screen.getAllByTestId('key-ips-display')
    expect(ips[0].textContent).toContain('1.2.3.4')
    expect(ips[0].textContent).toContain('+1')
    expect(ips[1].textContent).toContain('—')
    expect(screen.getByText('Never')).toBeInTheDocument()
  })
})

describe('AdminApiKeysPage — create', () => {
  it('disables submit until a name and user email are provided', () => {
    render(<AdminApiKeysPage />)
    openCreate()
    const card = screen.getByText('Create API Key').closest('div') as HTMLElement
    expect(within(card).getByText('Create Key').closest('button')).toBeDisabled()

    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Production API key'), {
      target: { value: 'My Key' },
    })
    expect(within(card).getByText('Create Key').closest('button')).not.toBeDisabled()
  })

  it('rejects invalid scope tokens without calling the API', async () => {
    render(<AdminApiKeysPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Production API key'), {
      target: { value: 'My Key' },
    })
    fireEvent.change(screen.getByTestId('key-scopes-custom-input'), {
      target: { value: 'bad,scope' },
    })
    fireEvent.click(screen.getAllByText('Add')[0])
    submitCreate()
    expect(await screen.findByTestId('apikey-form-error')).toBeInTheDocument()
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('creates a key, shows the secret + scope-filter warning, copies it and closes', async () => {
    mockApi.post.mockResolvedValueOnce({
      key_id: 'new-1',
      api_key: 'ak_plaintext_secret',
      name: 'My Key',
      key_prefix: 'ak_new',
      requested_scopes: ['read', 'write'],
      granted_scopes: ['read'],
      filtered_scopes: ['write'],
    })
    render(<AdminApiKeysPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Production API key'), {
      target: { value: 'My Key' },
    })
    fireEvent.change(screen.getByTestId('key-description-input'), { target: { value: 'backup' } })
    fireEvent.change(screen.getByTestId('key-allowed-ips-input'), {
      target: { value: '10.0.0.1, 10.0.0.2' },
    })
    fireEvent.change(screen.getByTestId('key-tier-input'), { target: { value: 'production' } })
    fireEvent.change(screen.getByPlaceholderText('365'), { target: { value: '30' } })
    submitCreate()

    expect(await screen.findByTestId('scope-filter-warning')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith(
      '/api/keys',
      expect.objectContaining({
        name: 'My Key',
        description: 'backup',
        user_email: 'user@example.com',
        allowed_ips: ['10.0.0.1', '10.0.0.2'],
        tier: 'production',
        expires_in_days: 30,
      }),
    )
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()

    fireEvent.click(screen.getByTitle('Copy key'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ak_plaintext_secret')

    fireEvent.click(screen.getByText('Done'))
    expect(screen.queryByText('API Key Created')).not.toBeInTheDocument()
  })

  it('omits the scope-filter warning when nothing was filtered', async () => {
    mockApi.post.mockResolvedValueOnce({
      key_id: 'new-2',
      api_key: 'ak_x',
      name: 'K',
      requested_scopes: ['read'],
      granted_scopes: ['read'],
      filtered_scopes: [],
    })
    render(<AdminApiKeysPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Production API key'), {
      target: { value: 'K' },
    })
    submitCreate()
    expect(await screen.findByText('API Key Created')).toBeInTheDocument()
    expect(screen.queryByTestId('scope-filter-warning')).not.toBeInTheDocument()
  })

  it('surfaces a create failure as a form error', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('create boom'))
    render(<AdminApiKeysPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText('user@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Production API key'), {
      target: { value: 'K' },
    })
    submitCreate()
    expect(await screen.findByText('create boom')).toBeInTheDocument()
  })

  it('closes the create modal via Cancel and via the backdrop', () => {
    render(<AdminApiKeysPage />)
    openCreate()
    const card = screen.getByText('Create API Key').closest('div') as HTMLElement
    fireEvent.click(within(card).getByText('Cancel'))
    expect(screen.queryByText('Create API Key')).not.toBeInTheDocument()

    openCreate()
    const backdrop = screen.getByText('Create API Key').closest('.fixed')!.querySelector('.absolute')
    fireEvent.click(backdrop as HTMLElement)
    expect(screen.queryByText('Create API Key')).not.toBeInTheDocument()
  })
})

describe('AdminApiKeysPage — edit', () => {
  beforeEach(() => {
    mockQueryData.data = [makeKey()]
  })

  it('opens pre-filled and saves with never-expires', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    const nameInput = screen.getByTestId('key-edit-name-input') as HTMLInputElement
    expect(nameInput.value).toBe('Alpha')
    expect(screen.getByText(/currently:/)).toBeInTheDocument()

    fireEvent.change(nameInput, { target: { value: 'Renamed' } })
    fireEvent.click(screen.getByTestId('key-edit-never-expires-toggle'))
    fireEvent.click(screen.getByTestId('key-edit-submit'))

    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith(
        '/api/keys/k1',
        expect.objectContaining({ name: 'Renamed', never_expires: true }),
      ),
    )
    expect(notify.success).toHaveBeenCalledWith('Key updated.')
    await waitFor(() => expect(screen.queryByTestId('key-edit-modal')).not.toBeInTheDocument())
  })

  it('sends expires_in_days and the edited fields', async () => {
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    fireEvent.change(screen.getByTestId('key-edit-description-input'), {
      target: { value: 'new description' },
    })
    fireEvent.change(screen.getByTestId('key-edit-allowed-ips-input'), {
      target: { value: '10.0.0.9' },
    })
    fireEvent.change(screen.getByTestId('key-edit-tier-input'), { target: { value: 'staging' } })
    fireEvent.change(screen.getByTestId('key-edit-expires-input'), { target: { value: '30' } })
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith(
        '/api/keys/k1',
        expect.objectContaining({
          description: 'new description',
          allowed_ips: ['10.0.0.9'],
          tier: 'staging',
          expires_in_days: 30,
        }),
      ),
    )
  })

  it('checks never-expires for a key without an expiry', () => {
    mockQueryData.data = [makeKey({ expires_at: null, never_expires: true })]
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    expect(screen.getByTestId('key-edit-never-expires-toggle')).toBeChecked()
    expect(screen.queryByText(/currently:/)).not.toBeInTheDocument()
  })

  it('rejects invalid scope tokens on edit', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    fireEvent.change(screen.getByTestId('key-edit-scopes-custom-input'), {
      target: { value: 'nope,comma' },
    })
    fireEvent.click(screen.getAllByText('Add')[0])
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() => expect(notify.error).toHaveBeenCalled())
    expect(mockApi.patch).not.toHaveBeenCalled()
  })

  it('toasts an edit failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.patch.mockRejectedValueOnce(new Error('update failed'))
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('update failed'))
  })

  it('closes the edit modal via Cancel and via the close icon', () => {
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('key-edit-btn'))
    fireEvent.click(screen.getByLabelText('Close'))
    expect(screen.queryByTestId('key-edit-modal')).not.toBeInTheDocument()

    fireEvent.click(screen.getByTestId('key-edit-btn'))
    const card = screen.getByTestId('key-edit-modal')
    fireEvent.click(within(card).getByText('Cancel'))
    expect(screen.queryByTestId('key-edit-modal')).not.toBeInTheDocument()
  })
})

describe('AdminApiKeysPage — revoke / restore', () => {
  it('deactivates an active key via the confirm dialog', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.data = [makeKey()]
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Deactivate key (reversible)'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalledWith('/api/keys/k1/revoke'))
    expect(notify.success).toHaveBeenCalledWith('Key revoked. You can restore it later if needed.')
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.data = [makeKey()]
    mockApi.post.mockRejectedValueOnce(new Error('revoke failed'))
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Deactivate key (reversible)'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke failed'))
  })

  it('reactivates an inactive key', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.data = [makeKey({ is_active: false })]
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Reactivate key'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith('/api/keys/k1', { is_active: true }),
    )
    expect(notify.success).toHaveBeenCalledWith('Key restored successfully.')
  })

  it('toasts a restore failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.data = [makeKey({ is_active: false })]
    mockApi.patch.mockRejectedValueOnce(new Error('restore failed'))
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Reactivate key'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('restore failed'))
  })

  it('cancels the revoke and restore confirmations', () => {
    mockQueryData.data = [makeKey()]
    const { rerender } = render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Deactivate key (reversible)'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()

    mockQueryData.data = [makeKey({ is_active: false })]
    rerender(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Reactivate key'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.patch).not.toHaveBeenCalled()
  })
})

describe('AdminApiKeysPage — delete / rotate dialogs', () => {
  beforeEach(() => {
    mockQueryData.data = [makeKey()]
  })

  it('deletes a key through the safeword dialog', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Delete key permanently (irreversible)'))
    expect(screen.getByTestId('rsd-api_key_delete-label').textContent).toBe('Alpha')
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-success'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Key deleted successfully.'))
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()
  })

  it('closes the delete dialog without deleting', () => {
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Delete key permanently (irreversible)'))
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-close'))
    expect(screen.queryByTestId('rsd-api_key_delete')).not.toBeInTheDocument()
  })

  it('toasts a delete-dialog error', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTitle('Delete key permanently (irreversible)'))
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-error'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('boom'))
  })

  it('rotates a key and shows the new secret once', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('rotate-key-btn'))
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-success'))
    expect(await screen.findByTestId('rotated-key-modal')).toBeInTheDocument()
    expect(screen.getByTestId('rotated-key-value').textContent).toBe('NEW-SECRET')
    expect(notify.success).toHaveBeenCalledWith('Secret rotated. Copy it now.')

    fireEvent.click(screen.getByTestId('rotated-key-copy'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('NEW-SECRET')

    fireEvent.click(screen.getByTestId('rotated-key-done'))
    expect(screen.queryByTestId('rotated-key-modal')).not.toBeInTheDocument()
  })

  it('closes the rotate dialog and surfaces its error', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('rotate-key-btn'))
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-close'))
    expect(screen.queryByTestId('rsd-api_key_rotate')).not.toBeInTheDocument()

    fireEvent.click(screen.getByTestId('rotate-key-btn'))
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-error'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('boom'))
  })

  it('closes the rotated-secret modal via the backdrop', async () => {
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('rotate-key-btn'))
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-success'))
    const modal = await screen.findByTestId('rotated-key-modal')
    fireEvent.click(modal.querySelector('.absolute.inset-0') as HTMLElement)
    expect(screen.queryByTestId('rotated-key-modal')).not.toBeInTheDocument()
  })
})

describe('AdminApiKeysPage — cleanup and claims', () => {
  it('cleans up expired keys', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalledWith('/api/admin/keys/cleanup'))
    expect(notify.success).toHaveBeenCalledWith('Expired keys cleaned up.')
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()
  })

  it('toasts a cleanup failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockApi.post.mockRejectedValueOnce(new Error('cleanup failed'))
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByText('Cleanup Expired'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('cleanup failed'))
  })

  it('opens and closes the claims editor', () => {
    mockQueryData.data = [makeKey()]
    render(<AdminApiKeysPage />)
    fireEvent.click(screen.getByTestId('open-claims-btn'))
    const claims = screen.getByTestId('claims-tab')
    expect(claims).toBeInTheDocument()
    expect(within(claims).getByText('Alpha')).toBeInTheDocument()
    fireEvent.click(screen.getByText('close-claims'))
    expect(screen.queryByTestId('claims-tab')).not.toBeInTheDocument()
  })
})
