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

vi.mock('@/lib/api', () => ({
  api: mockApi,
}))

vi.mock('@/hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-oauth-clients') {
      return { data: mockQueryData.clients, refetch: mockQueryData.refetch, isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('@/hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}))

vi.mock('@/stores/toastStore', () => ({
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
