// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AdminFederationPage } from './AdminFederationPage'

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({ scopes: [] }),
  post: vi.fn().mockResolvedValue({}),
  put: vi.fn().mockResolvedValue({}),
  patch: vi.fn().mockResolvedValue({}),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  providers: [] as Array<Record<string, unknown>>,
  refetch: vi.fn(),
}))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({ data: mockQueryData.providers, refetch: mockQueryData.refetch }),
}))
vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))

function makeProvider(overrides: Record<string, unknown> = {}) {
  return {
    id: 'p1',
    label: 'CIE',
    description: 'Carta d\u2019Identita',
    issuer: 'https://idp.example',
    client_id: 'client-1',
    scopes: ['openid', 'email'],
    icon_uri: null,
    logo_uri: null,
    enabled: true,
    auth_levels: ['l1', 'l2'],
    visible_contexts: ['dashboard', 'oauth2'],
    claims_mapping: { sub: 'external_id', email: 'email' },
    rate_limit_per_minute: 60,
    created_at: '',
    updated_at: '',
    ...overrides,
  }
}

function openCreate() {
  fireEvent.click(screen.getByText('Add Provider'))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQueryData.providers = []
  mockApi.get.mockResolvedValue({ scopes: [] })
  mockApi.post.mockResolvedValue({})
  mockApi.put.mockResolvedValue({})
  mockApi.patch.mockResolvedValue({})
  mockApi.delete.mockResolvedValue({})
})

describe('AdminFederationPage — render', () => {
  it('shows the empty state', () => {
    render(<AdminFederationPage />)
    expect(screen.getByText('No providers configured. Add your first one.')).toBeInTheDocument()
  })

  it('renders provider rows with labels, scopes and status', () => {
    mockQueryData.providers = [
      makeProvider(),
      makeProvider({ id: 'p2', label: 'SPID', enabled: false, description: null, icon_uri: 'https://x/i.png' }),
    ]
    render(<AdminFederationPage />)
    expect(screen.getByText('CIE')).toBeInTheDocument()
    expect(screen.getByText('SPID')).toBeInTheDocument()
    expect(screen.getByText('Active')).toBeInTheDocument()
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    expect(screen.getByText('Carta d\u2019Identita')).toBeInTheDocument()
    expect(screen.getAllByText('openid').length).toBeGreaterThan(0)
  })

  it('hides a broken provider icon on error', () => {
    mockQueryData.providers = [makeProvider({ icon_uri: 'https://x/i.png' })]
    render(<AdminFederationPage />)
    const img = document.querySelector('img') as HTMLImageElement
    fireEvent.error(img)
    expect(img.style.display).toBe('none')
  })
})

describe('AdminFederationPage — create', () => {
  it('creates a provider and closes the form', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminFederationPage />)
    openCreate()
    expect(screen.getByText('New Provider')).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText('CIE'), { target: { value: 'Google' } })
    fireEvent.change(screen.getByPlaceholderText('https://accounts.google.com'), {
      target: { value: 'https://accounts.google.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('your-client-id'), { target: { value: 'cid' } })
    fireEvent.change(screen.getByPlaceholderText('\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf'), {
      target: { value: 'secret' },
    })
    fireEvent.click(screen.getByText('Save'))

    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    const body = mockApi.post.mock.calls[0][1] as Record<string, unknown>
    expect(body.label).toBe('Google')
    expect(body.issuer).toBe('https://accounts.google.com')
    expect(body.client_id).toBe('cid')
    expect(body.client_secret).toBe('secret')
    expect(body.auth_levels).toBeNull()
    expect(notify.success).toHaveBeenCalledWith('Provider created.')
    expect(mockQueryData.refetch).toHaveBeenCalled()
    expect(screen.queryByText('New Provider')).not.toBeInTheDocument()
  })

  it('falls back to the issuer when no client secret is given', async () => {
    render(<AdminFederationPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText('CIE'), { target: { value: 'X' } })
    fireEvent.change(screen.getByPlaceholderText('your-client-id'), { target: { value: 'cid' } })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    expect((mockApi.post.mock.calls[0][1] as Record<string, unknown>).client_secret).toBe('')
  })

  it('rejects invalid claims-mapping JSON', async () => {
    render(<AdminFederationPage />)
    openCreate()
    fireEvent.change(screen.getByPlaceholderText(/IdP claim/), { target: { value: '{bad' } })
    fireEvent.click(screen.getByText('Save'))
    expect(await screen.findByText('Invalid JSON in Claims Mapping')).toBeInTheDocument()
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('surfaces a create failure in the form error banner', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('create boom'))
    render(<AdminFederationPage />)
    openCreate()
    fireEvent.click(screen.getByText('Save'))
    expect(await screen.findByText('create boom')).toBeInTheDocument()
  })

  it('toggles the visible-in checkboxes', async () => {
    render(<AdminFederationPage />)
    openCreate()
    fireEvent.click(screen.getByLabelText('Dashboard'))
    fireEvent.change(screen.getByPlaceholderText('Default'), { target: { value: '30' } })
    fireEvent.change(screen.getByPlaceholderText(/SpidL1/), {
      target: { value: 'l1 l2' },
    })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    const body = mockApi.post.mock.calls[0][1] as Record<string, unknown>
    expect(body.visible_contexts).toEqual(['oauth2'])
    expect(body.rate_limit_per_minute).toBe(30)
    expect(body.auth_levels).toEqual(['l1', 'l2'])
  })

  it('closes the form via Cancel and the backdrop', () => {
    render(<AdminFederationPage />)
    openCreate()
    fireEvent.click(screen.getByText('Cancel'))
    expect(screen.queryByText('New Provider')).not.toBeInTheDocument()

    openCreate()
    fireEvent.click(screen.getByText('New Provider').closest('.fixed')!.querySelector('.absolute') as HTMLElement)
    expect(screen.queryByText('New Provider')).not.toBeInTheDocument()
  })
})

describe('AdminFederationPage — edit', () => {
  beforeEach(() => {
    mockQueryData.providers = [makeProvider()]
  })

  it('opens pre-filled and updates the provider', async () => {
    const { notify } = await import('../../stores/toastStore')
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Edit'))
    expect(screen.getByText('Edit Provider')).toBeInTheDocument()
    const label = screen.getByPlaceholderText('CIE') as HTMLInputElement
    expect(label.value).toBe('CIE')
    expect(screen.getByPlaceholderText(/IdP claim/)).toHaveValue(
      JSON.stringify({ sub: 'external_id', email: 'email' }, null, 2),
    )

    fireEvent.change(label, { target: { value: 'CIE v2' } })
    fireEvent.change(screen.getByPlaceholderText('\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf\u25cf'), {
      target: { value: 'new-secret' },
    })
    fireEvent.click(screen.getByText('Save'))

    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const body = mockApi.put.mock.calls[0][1] as Record<string, unknown>
    expect(body.label).toBe('CIE v2')
    expect(body.client_secret).toBe('new-secret')
    expect(body.auth_levels).toEqual(['l1', 'l2'])
    expect(notify.success).toHaveBeenCalledWith('Provider updated.')
  })

  it('omits client_secret when unchanged and defaults missing visible contexts', async () => {
    mockQueryData.providers = [makeProvider({ visible_contexts: undefined })]
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Edit'))
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    const body = mockApi.put.mock.calls[0][1] as Record<string, unknown>
    expect(body).not.toHaveProperty('client_secret')
    expect(body.visible_contexts).toEqual(['dashboard', 'oauth2'])
  })

  it('resets a claims mapping left blank on edit', async () => {
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Edit'))
    fireEvent.change(screen.getByPlaceholderText(/IdP claim/), { target: { value: '   ' } })
    fireEvent.click(screen.getByText('Save'))
    await waitFor(() => expect(mockApi.put).toHaveBeenCalled())
    expect((mockApi.put.mock.calls[0][1] as Record<string, unknown>).claims_mapping).toEqual({
      sub: 'external_id',
      email: 'email',
    })
  })
})

describe('AdminFederationPage — toggle', () => {
  it('disables an active provider', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.providers = [makeProvider({ enabled: true })]
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Disable'))
    await waitFor(() =>
      expect(mockApi.patch).toHaveBeenCalledWith('/api/federation/admin/providers/p1/toggle', {}),
    )
    expect(notify.success).toHaveBeenCalledWith('Provider disabled.')
  })

  it('enables a disabled provider', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.providers = [makeProvider({ enabled: false })]
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Enable'))
    await waitFor(() => expect(mockApi.patch).toHaveBeenCalled())
    expect(notify.success).toHaveBeenCalledWith('Provider enabled.')
  })

  it('toasts a toggle failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.providers = [makeProvider()]
    mockApi.patch.mockRejectedValueOnce(new Error('toggle failed'))
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Disable'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('toggle failed'))
  })
})

describe('AdminFederationPage — delete', () => {
  it('deletes a provider after confirmation', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.providers = [makeProvider()]
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Delete'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() =>
      expect(mockApi.delete).toHaveBeenCalledWith('/api/federation/admin/providers/p1'),
    )
    expect(notify.success).toHaveBeenCalledWith('Provider deleted.')
  })

  it('toasts a delete failure', async () => {
    const { notify } = await import('../../stores/toastStore')
    mockQueryData.providers = [makeProvider()]
    mockApi.delete.mockRejectedValueOnce(new Error('delete failed'))
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Delete'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(notify.error).toHaveBeenCalledWith('delete failed'))
  })

  it('cancels the delete confirmation', () => {
    mockQueryData.providers = [makeProvider()]
    render(<AdminFederationPage />)
    fireEvent.click(screen.getByTitle('Delete'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })
})
