// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminOAuthClientsPage } from './AdminOAuthClientsPage'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockApi = vi.hoisted(() => ({
  get: vi.fn().mockResolvedValue({ items: [] }),
  put: vi.fn().mockResolvedValue({}),
  post: vi.fn().mockResolvedValue({ client_id: 'c1', client_secret: 'plain-secret' }),
  delete: vi.fn().mockResolvedValue({}),
}))

const mockQueryData = vi.hoisted(() => ({
  clients: [] as Array<Record<string, unknown>>,
  refetch: vi.fn(),
}))

vi.mock('../../lib/api', () => ({
  api: mockApi,
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-oauth-clients') {
      return { data: mockQueryData.clients, refetch: mockQueryData.refetch, isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../../hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn(), info: vi.fn() },
}))


describe('AdminOAuthClientsPage — T.3 DPoP toggle', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.clients = []
  })

  it('renders the DPoP toggle inside the form', async () => {
    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)
    // Open the create form
    const createBtn = screen.getByTestId('create-oauth-client-btn')
    fireEvent.click(createBtn)
    // The toggle is inside the security panel
    const toggle = await screen.findByTestId('dpop-bound-toggle')
    expect(toggle).toBeInTheDocument()
    // Default off
    expect((toggle as HTMLInputElement).checked).toBe(false)
  })

  it('includes dpop_bound=false in the create payload when toggle is off', async () => {
    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)
    const createBtn = screen.getByTestId('create-oauth-client-btn')
    fireEvent.click(createBtn)
    await screen.findByTestId('dpop-bound-toggle')

    // Fill the required fields and submit
    fireEvent.change(screen.getByTestId('client-name-input'), {
      target: { value: 'DPoP Test Client' },
    })
    // The grant_type authorization_code checkbox is required for PKCE.
    fireEvent.click(screen.getByTestId('grant-authorization_code'))
    // authorization_code also requires at least one redirect URI
    fireEvent.change(screen.getByTestId('client-uri-input-0'), {
      target: { value: 'https://example.com/cb' },
    })
    fireEvent.click(screen.getByTestId('create-client-submit'))

    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    const [_url, payload] = mockApi.post.mock.calls[0]
    expect(payload).toMatchObject({ dpop_bound: false })
  })

  it('includes dpop_bound=true in the create payload when toggle is on', async () => {
    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)
    const createBtn = screen.getByTestId('create-oauth-client-btn')
    fireEvent.click(createBtn)
    const toggle = await screen.findByTestId('dpop-bound-toggle')

    // Flip the toggle
    fireEvent.click(toggle)
    expect((toggle as HTMLInputElement).checked).toBe(true)

    // Fill required fields
    fireEvent.change(screen.getByTestId('client-name-input'), {
      target: { value: 'DPoP-Required Client' },
    })
    fireEvent.click(screen.getByTestId('grant-authorization_code'))
    fireEvent.change(screen.getByTestId('client-uri-input-0'), {
      target: { value: 'https://example.com/cb' },
    })
    fireEvent.click(screen.getByTestId('create-client-submit'))

    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    const [_url, payload] = mockApi.post.mock.calls[0]
    expect(payload).toMatchObject({ dpop_bound: true })
  })

  it('shows a DPoP badge in the table for DPoP-bound clients', () => {
    mockQueryData.clients = [
      {
        client_id: 'dpop-1',
        client_name: 'DPoP-Required Client',
        is_confidential: true,
        redirect_uris: ['https://example.com/cb'],
        grant_types: ['authorization_code'],
        allowed_scopes: ['read'],
        is_active: true,
        dpop_bound: true,
      },
      {
        client_id: 'plain-1',
        client_name: 'Plain Client',
        is_confidential: true,
        redirect_uris: ['https://example.com/cb'],
        grant_types: ['authorization_code'],
        allowed_scopes: ['read'],
        is_active: true,
        dpop_bound: false,
      },
    ]

    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    // Both clients are rendered. The DPoP-bound one carries the
    // ``dpop-badge`` testid; the plain one does not.
    const badges = screen.getAllByTestId('dpop-badge')
    expect(badges).toHaveLength(1)
  })
})


describe('AdminOAuthClientsPage — Rotate Secret', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQueryData.clients = [
      {
        client_id: 'c1',
        client_name: 'Existing Client',
        is_confidential: true,
        redirect_uris: ['https://example.com/cb'],
        grant_types: ['authorization_code'],
        allowed_scopes: ['read'],
        is_active: true,
        token_endpoint_auth_method: 'client_secret_basic',
        has_client_secret_jwt_key: false,
        dpop_bound: false,
      },
    ]
  })

  it('opens the rotate dialog but does not call any POST on click', () => {
    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))

    // The dialog is open and on the confirm phase.
    expect(screen.getByTestId('rotate-secret-dialog')).toBeInTheDocument()
    expect(screen.getByTestId('rotate-secret-generate')).toBeInTheDocument()

    // The destructive POST must NOT have fired yet — neither to
    // issue a challenge nor to perform the rotation.
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('Generate safeword calls /challenge and moves to the safeword phase', async () => {
    mockApi.post.mockResolvedValueOnce({
      challenge_id: 'challenge-xyz',
      word: 'correct-horse-purple-42',
      expires_at: '2099-01-01T00:00:00Z',
    })

    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))
    fireEvent.click(screen.getByTestId('rotate-secret-generate'))

    await waitFor(() => {
      expect(screen.getByTestId('rotate-secret-safeword-phase')).toBeInTheDocument()
    })

    // The challenge endpoint was called.
    expect(mockApi.post).toHaveBeenCalledWith(
      '/api/oauth-clients/c1/rotate-secret/challenge'
    )

    // The word is rendered in a code block the admin can copy.
    const wordEl = screen.getByTestId('rotate-secret-word')
    expect(wordEl.textContent).toContain('correct-horse-purple-42')
  })

  it('keeps the Rotate button disabled until the safeword is typed exactly', async () => {
    mockApi.post.mockResolvedValueOnce({
      challenge_id: 'challenge-xyz',
      word: 'correct-horse-purple-42',
      expires_at: '2099-01-01T00:00:00Z',
    })

    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))
    fireEvent.click(screen.getByTestId('rotate-secret-generate'))
    await screen.findByTestId('rotate-secret-safeword-phase')

    const input = screen.getByTestId('rotate-secret-input') as HTMLInputElement
    const confirmBtn = screen.getByTestId('rotate-secret-confirm') as HTMLButtonElement

    // Empty input → button disabled
    expect(confirmBtn.disabled).toBe(true)

    // Wrong word → button still disabled
    fireEvent.change(input, { target: { value: 'wrong-word-99' } })
    expect(confirmBtn.disabled).toBe(true)
    expect(screen.getByTestId('rotate-secret-mismatch')).toBeInTheDocument()

    // Correct word → button enabled
    fireEvent.change(input, { target: { value: 'correct-horse-purple-42' } })
    expect(confirmBtn.disabled).toBe(false)
  })

  it('calls the rotate POST with {challenge_id, word} only after the safeword is typed', async () => {
    // First call: challenge request
    mockApi.post.mockResolvedValueOnce({
      challenge_id: 'challenge-xyz',
      word: 'correct-horse-purple-42',
      expires_at: '2099-01-01T00:00:00Z',
    })
    // Second call: rotate with the typed safeword
    mockApi.post.mockResolvedValueOnce({
      client_id: 'c1',
      new_client_secret: 'rotated-secret-abc123',
    })

    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))
    fireEvent.click(screen.getByTestId('rotate-secret-generate'))
    await screen.findByTestId('rotate-secret-safeword-phase')

    const input = screen.getByTestId('rotate-secret-input') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'correct-horse-purple-42' } })

    fireEvent.click(screen.getByTestId('rotate-secret-confirm'))

    // Modal with the new secret opens
    const modal = await screen.findByTestId('client-created-secret')
    expect(modal.textContent).toContain('rotated-secret-abc123')

    // The destructive POST was called with the right body.
    const rotateCall = mockApi.post.mock.calls.find(
      (c) => c[0] === '/api/oauth-clients/c1/rotate-secret'
    )
    expect(rotateCall).toBeDefined()
    expect(rotateCall?.[1]).toEqual({
      challenge_id: 'challenge-xyz',
      word: 'correct-horse-purple-42',
    })
  })

  it('does not call any rotate POST when the admin cancels from the confirm phase', () => {
    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))
    expect(screen.getByTestId('rotate-secret-dialog')).toBeInTheDocument()

    // Click Cancel
    fireEvent.click(screen.getByText('Cancel'))

    expect(mockApi.post).not.toHaveBeenCalled()
    expect(screen.queryByTestId('rotate-secret-dialog')).not.toBeInTheDocument()
  })

  it('on rotate failure (400 expired) shows the error phase and lets the admin retry', async () => {
    const { notify } = await import('../../stores/toastStore')

    // First call: challenge issued
    mockApi.post.mockResolvedValueOnce({
      challenge_id: 'challenge-xyz',
      word: 'correct-horse-purple-42',
      expires_at: '2099-01-01T00:00:00Z',
    })
    // Second call: rotate returns 400 (ApiError with status 400)
    class FakeApiError extends Error {
      status: number
      constructor(message: string, status: number) {
        super(message)
        this.status = status
      }
    }
    mockApi.post.mockRejectedValueOnce(
      new FakeApiError('Challenge expired. Please generate a new safeword.', 400)
    )

    render(<Wrapper><AdminOAuthClientsPage /></Wrapper>)

    fireEvent.click(screen.getByTestId('rotate-secret-btn'))
    fireEvent.click(screen.getByTestId('rotate-secret-generate'))
    await screen.findByTestId('rotate-secret-safeword-phase')

    const input = screen.getByTestId('rotate-secret-input') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'correct-horse-purple-42' } })
    fireEvent.click(screen.getByTestId('rotate-secret-confirm'))

    // The error phase is shown with the backend message.
    const errPhase = await screen.findByTestId('rotate-secret-error-phase')
    expect(errPhase).toBeInTheDocument()
    expect(screen.getByTestId('rotate-secret-error-message').textContent).toContain(
      'Challenge expired'
    )

    // The admin is offered a retry path back to the confirm phase.
    expect(screen.getByTestId('rotate-secret-retry')).toBeInTheDocument()

    // The error was also surfaced as a toast.
    await waitFor(() => {
      expect(notify.error).toHaveBeenCalled()
    })
  })
})
