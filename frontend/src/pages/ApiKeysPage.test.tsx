// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiKeysPage } from './ApiKeysPage'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({ scopes: ['read', 'write'] }),
  post: vi.fn().mockResolvedValue({}),
  patch: vi.fn().mockResolvedValue({}),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  keys: [] as Array<Record<string, unknown>>,
  refetch: vi.fn(),
  invalidateApiKeyLists: vi.fn(),
}))

vi.mock('../lib/api', () => ({ api: mockApi }))

vi.mock('../hooks/useApi', () => ({
  useApiQuery: () => ({ data: mockQueryData.keys, refetch: mockQueryData.refetch, isLoading: false }),
  useApiKeyInvalidation: () => ({ invalidateApiKeyLists: mockQueryData.invalidateApiKeyLists }),
}))

vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

// Lightweight stand-in: the real dialog owns its own multi-phase safeword
// flow (out of scope here). The stub exposes the callbacks the page wires.
vi.mock('../components/admin/RotateSecretDialog', () => ({
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

function makeKey(overrides: Record<string, unknown> = {}) {
  return {
    key_id: 'k1',
    name: 'Alpha',
    description: 'desc',
    scopes: ['read', 'write'],
    key_prefix: 'ak_abc',
    is_active: true,
    expires_at: '2030-01-01T00:00:00Z',
    never_expires: false,
    last_used_at: '2026-09-01T00:00:00Z',
    created_at: '2025-01-01T00:00:00Z',
    allowed_ips: ['1.2.3.4', '5.6.7.8'],
    ...overrides,
  }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQueryData.keys = []
  mockApi.get.mockResolvedValue({ scopes: ['read', 'write'] })
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn() },
    configurable: true,
  })
})

describe('ApiKeysPage — render', () => {
  it('shows the empty state when there are no keys', () => {
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    expect(screen.getByText('No API keys')).toBeInTheDocument()
    expect(screen.getByTestId('create-api-key-btn')).toBeInTheDocument()
  })

  it('renders key rows with scopes, IP restriction, status and dates', () => {
    mockQueryData.keys = [
      makeKey(),
      makeKey({
        key_id: 'k2',
        name: 'Beta',
        description: null,
        scopes: ['read'],
        key_prefix: '',
        is_active: false,
        expires_at: null,
        last_used_at: null,
        allowed_ips: [],
      }),
    ]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    expect(screen.getAllByTestId('api-key-row')).toHaveLength(4)
    expect(screen.getAllByText('Alpha').length).toBeGreaterThan(0)
    expect(screen.getAllByTestId('key-ips-display')[0].textContent).toContain('1.2.3.4')
    expect(screen.getAllByTestId('key-ips-display')[0].textContent).toContain('+1')
    expect(screen.getAllByText('Never').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Inactive').length).toBeGreaterThan(0)
  })

  it('shows the at-risk banner for active keys without expiry', () => {
    mockQueryData.keys = [makeKey({ expires_at: null, last_used_at: null })]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    expect(screen.getByText(/may need attention/)).toBeInTheDocument()
  })
})

describe('ApiKeysPage — create', () => {
  it('rejects invalid scope tokens without calling the API', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('create-api-key-btn'))
    fireEvent.change(screen.getByTestId('key-scopes-custom-input'), {
      target: { value: 'bad,scope' },
    })
    fireEvent.click(screen.getByText('Add'))
    fireEvent.click(screen.getByTestId('key-create-submit'))

    await waitFor(() => expect(notify.error).toHaveBeenCalled())
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('creates a key, shows the secret + scope-filter warning, and copies it', async () => {
    mockApi.post.mockResolvedValueOnce({
      key_id: 'new-1',
      api_key: 'ak_plaintext_secret',
      name: 'My Key',
      requested_scopes: ['read', 'write'],
      granted_scopes: ['read'],
      filtered_scopes: ['write'],
    })
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('create-api-key-btn'))
    fireEvent.change(screen.getByTestId('key-name-input'), { target: { value: 'My Key' } })
    fireEvent.change(screen.getByTestId('key-description-input'), {
      target: { value: 'backup' },
    })
    fireEvent.change(screen.getByTestId('key-allowed-ips-input'), {
      target: { value: '10.0.0.1, 10.0.0.2' },
    })
    fireEvent.change(screen.getByPlaceholderText('Expires in days (optional)'), {
      target: { value: '30' },
    })
    fireEvent.click(screen.getByTestId('key-create-submit'))

    await waitFor(() => expect(screen.getByTestId('key-created-display')).toBeInTheDocument())
    expect(screen.getByTestId('scope-filter-warning')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith(
      '/api/keys',
      expect.objectContaining({
        name: 'My Key',
        description: 'backup',
        allowed_ips: ['10.0.0.1', '10.0.0.2'],
        expires_in_days: 30,
      }),
    )
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()

    fireEvent.click(screen.getByTestId('key-created-done'))
    expect(screen.queryByTestId('key-created-display')).not.toBeInTheDocument()
  })

  it('surfaces a create failure as a toast', async () => {
    const { notify } = await import('../stores/toastStore')
    mockApi.post.mockRejectedValueOnce(new Error('boom'))
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('create-api-key-btn'))
    fireEvent.click(screen.getByTestId('key-create-submit'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('boom'))
  })
})

describe('ApiKeysPage — edit', () => {
  beforeEach(() => {
    mockQueryData.keys = [makeKey()]
  })

  it('opens the edit modal pre-filled and saves changes', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[0])
    expect(screen.getByTestId('key-edit-modal')).toBeInTheDocument()
    const nameInput = screen.getByTestId('key-edit-name-input') as HTMLInputElement
    expect(nameInput.value).toBe('Alpha')

    fireEvent.change(nameInput, { target: { value: 'Renamed' } })
    fireEvent.click(screen.getByTestId('key-edit-never-expires-toggle'))
    fireEvent.click(screen.getByTestId('key-edit-submit'))

    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith(
        '/api/keys/k1',
        expect.objectContaining({ name: 'Renamed', never_expires: true }),
      ),
    )
    expect(notify.success).toHaveBeenCalled()
    await waitFor(() => expect(screen.queryByTestId('key-edit-modal')).not.toBeInTheDocument())
  })

  it('rejects invalid scope tokens on edit', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[0])
    fireEvent.change(screen.getByTestId('key-edit-scopes-custom-input'), {
      target: { value: 'nope,comma' },
    })
    fireEvent.click(screen.getByText('Add'))
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() => expect(notify.error).toHaveBeenCalled())
    expect(mockApi.patch).not.toHaveBeenCalled()
  })

  it('closes the edit modal via Cancel', () => {
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[0])
    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByTestId('key-edit-modal')).not.toBeInTheDocument()
  })
})

describe('ApiKeysPage — revoke / restore', () => {
  it('deactivates an active key via the confirm dialog', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('revoke-key-btn')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalledWith('/api/keys/k1/revoke'))
    expect(notify.success).toHaveBeenCalledWith('Key deactivated.')
  })

  it('restores an inactive key', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey({ is_active: false })]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Restore key')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith('/api/keys/k1', { is_active: true }),
    )
    expect(notify.success).toHaveBeenCalledWith('Key restored.')
  })
})

describe('ApiKeysPage — delete / rotate dialogs', () => {
  beforeEach(() => {
    mockQueryData.keys = [makeKey()]
  })

  it('deletes a key through the safeword dialog and refetches', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Delete key')[0])
    expect(screen.getByTestId('rsd-api_key_delete-label').textContent).toBe('Alpha')
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-success'))
    await waitFor(() => expect(notify.success).toHaveBeenCalledWith('Key deleted.'))
    expect(mockQueryData.invalidateApiKeyLists).toHaveBeenCalled()
  })

  it('rotates a key and shows the new secret once', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('rotate-key-btn')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-success'))
    await waitFor(() => expect(screen.getByTestId('rotated-key-modal')).toBeInTheDocument())
    expect(screen.getByTestId('rotated-key-value').textContent).toBe('NEW-SECRET')
    expect(notify.success).toHaveBeenCalledWith('Secret rotated. Copy it now.')

    fireEvent.click(screen.getByTestId('rotated-key-copy'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('NEW-SECRET')

    fireEvent.click(screen.getByTestId('rotated-key-done'))
    expect(screen.queryByTestId('rotated-key-modal')).not.toBeInTheDocument()
  })

  it('surfaces a rotate error as a toast', async () => {
    const { notify } = await import('../stores/toastStore')
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('rotate-key-btn')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-error'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('boom'))
  })

  it('closes the delete dialog without deleting', () => {
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Delete key')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-close'))
    expect(screen.queryByTestId('rsd-api_key_delete')).not.toBeInTheDocument()
  })
})

describe('ApiKeysPage — error and cancel branches', () => {
  it('copies the freshly created key to the clipboard', async () => {
    mockApi.post.mockResolvedValueOnce({
      key_id: 'new-1',
      api_key: 'ak_copy_me',
      name: 'My Key',
      requested_scopes: ['read'],
      granted_scopes: ['read'],
      filtered_scopes: [],
    })
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getByTestId('create-api-key-btn'))
    fireEvent.click(screen.getByTestId('key-create-submit'))
    const display = await screen.findByTestId('key-created-display')
    fireEvent.click(display.querySelectorAll('button')[0] as HTMLButtonElement)
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('ak_copy_me')
  })

  it('toasts an edit failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey()]
    mockApi.patch.mockRejectedValueOnce(new Error('update failed'))
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[0])
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('update failed'))
  })

  it('toasts a revoke failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey()]
    mockApi.post.mockRejectedValueOnce(new Error('revoke failed'))
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('revoke-key-btn')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('revoke failed'))
  })

  it('toasts a restore failure', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey({ is_active: false })]
    mockApi.patch.mockRejectedValueOnce(new Error('restore failed'))
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Restore key')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('restore failed'))
  })

  it('cancels the revoke confirmation without calling the API', () => {
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('revoke-key-btn')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.post).not.toHaveBeenCalled()
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
  })

  it('cancels the restore confirmation without calling the API', () => {
    mockQueryData.keys = [makeKey({ is_active: false })]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Restore key')[0])
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.patch).not.toHaveBeenCalled()
  })

  it('toasts a delete-dialog error', async () => {
    const { notify } = await import('../stores/toastStore')
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Delete key')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_delete-error'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('boom'))
  })

  it('closes the rotate dialog via its close control', () => {
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('rotate-key-btn')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-close'))
    expect(screen.queryByTestId('rsd-api_key_rotate')).not.toBeInTheDocument()
  })

  it('closes the rotated-secret modal via the backdrop', async () => {
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('rotate-key-btn')[0])
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-success'))
    const modal = await screen.findByTestId('rotated-key-modal')
    const backdrop = modal.querySelector('.absolute.inset-0') as HTMLElement
    fireEvent.click(backdrop)
    expect(screen.queryByTestId('rotated-key-modal')).not.toBeInTheDocument()
  })

  it('sends expires_in_days and the edited fields on save', async () => {
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[0])
    fireEvent.change(screen.getByTestId('key-edit-description-input'), {
      target: { value: 'new description' },
    })
    fireEvent.change(screen.getByTestId('key-edit-allowed-ips-input'), {
      target: { value: '10.0.0.9' },
    })
    fireEvent.change(screen.getByTestId('key-edit-expires-input'), {
      target: { value: '30' },
    })
    fireEvent.click(screen.getByTestId('key-edit-submit'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith(
        '/api/keys/k1',
        expect.objectContaining({
          description: 'new description',
          allowed_ips: ['10.0.0.9'],
          expires_in_days: 30,
        }),
      ),
    )
  })
})

describe('ApiKeysPage — mobile action wiring', () => {
  it('wires the mobile edit / revoke / rotate / delete buttons', () => {
    mockQueryData.keys = [makeKey()]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    // Index 1 is the mobile card (index 0 is the desktop table row).
    fireEvent.click(screen.getAllByTestId('key-edit-btn')[1])
    expect(screen.getByTestId('key-edit-modal')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Cancel'))

    fireEvent.click(screen.getAllByTestId('revoke-key-btn')[1])
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))

    fireEvent.click(screen.getAllByTestId('rotate-key-btn')[1])
    expect(screen.getByTestId('rsd-api_key_rotate')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('rsd-api_key_rotate-close'))

    fireEvent.click(screen.getAllByLabelText('Delete key')[1])
    expect(screen.getByTestId('rsd-api_key_delete')).toBeInTheDocument()
  })

  it('wires the mobile restore button', () => {
    mockQueryData.keys = [makeKey({ is_active: false })]
    render(
      <Wrapper>
        <ApiKeysPage />
      </Wrapper>,
    )
    fireEvent.click(screen.getAllByLabelText('Restore key')[1])
    expect(screen.getByTestId('confirm-dialog')).toBeInTheDocument()
  })
})
