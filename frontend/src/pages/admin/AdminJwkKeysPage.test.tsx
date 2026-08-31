// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AdminJwkKeysPage } from './AdminJwkKeysPage'

function Wrapper({ children }: { children: React.ReactNode }) {
  return <QueryClientProvider client={new QueryClient()}>{children}</QueryClientProvider>
}

const mockQuery = vi.hoisted(() => ({
  adminKeys: undefined as unknown,
  jwksStatus: undefined as unknown,
}))

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (_key: string[], endpoint: string) => {
    if (endpoint === '/api/admin/jwk-keys') {
      return { data: mockQuery.adminKeys, refetch: vi.fn(), isLoading: false }
    }
    if (endpoint === '/oauth2/jwks/status') {
      return { data: mockQuery.jwksStatus, refetch: vi.fn(), isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn() },
}))

const KEYS = [
  {
    kid: 'kid-active-1',
    status: 'active',
    algorithm: 'RS256',
    key_size: 2048,
    created_at: '2026-08-01T10:00:00Z',
  },
  {
    kid: 'kid-verifying-1',
    status: 'verifying',
    algorithm: 'RS256',
    key_size: 2048,
    created_at: '2026-05-01T10:00:00Z',
    retired_at: '2026-08-01T10:00:00Z',
  },
  {
    kid: 'kid-revoked-1',
    status: 'revoked',
    algorithm: 'RS256',
    key_size: 2048,
    created_at: '2026-01-01T10:00:00Z',
    retired_at: '2026-03-01T10:00:00Z',
    revoked_at: '2026-04-01T10:00:00Z',
  },
]

describe('AdminJwkKeysPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQuery.adminKeys = [...KEYS]
    mockQuery.jwksStatus = {
      active_kid: 'kid-active-1',
      keys: [
        ...KEYS,
        // A second verifying key so published (3) < total (4).
        {
          kid: 'kid-verifying-2',
          status: 'verifying',
          algorithm: 'RS256',
          key_size: 2048,
          created_at: '2026-06-01T10:00:00Z',
          retired_at: '2026-07-01T10:00:00Z',
        },
      ],
    }
  })

  it('renders the status lifecycle legend', async () => {
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)
    const legend = await screen.findByTestId('jwks-status-legend')
    expect(legend.textContent).toContain('Active')
    expect(legend.textContent).toContain('signs new tokens')
    expect(legend.textContent).toContain('Verifying')
    expect(legend.textContent).toContain('validates tokens issued before a rotation')
    expect(legend.textContent).toContain('Revoked')
    expect(legend.textContent).toContain('client-facing JWKS')
  })

  it('renders the Public JWKS card with the active kid and published count', async () => {
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)
    expect(await screen.findByTestId('jwks-public-card')).toBeInTheDocument()
    expect(screen.getByTestId('jwks-active-kid').textContent).toBe('kid-active-1')
    // 4 keys in the ring, 1 revoked → 3 published to clients.
    expect(screen.getByTestId('jwks-published-count').textContent).toContain(
      '3 of 4 keys published',
    )
    expect(screen.getByTestId('jwks-published-count').textContent).toContain(
      'revoked keys are excluded',
    )
  })

  it('links to the public JWKS endpoint', async () => {
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)
    const link = await screen.findByTestId('jwks-public-link')
    // API_URL is prefixed by the environment (VITE_API_URL); assert on the path.
    expect(link.getAttribute('href')).toMatch(/\/\.well-known\/jwks\.json$/)
    expect(link.getAttribute('target')).toBe('_blank')
  })

  it('renders all keys with the revoked one dimmed and its revocation date', async () => {
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)
    const rows = await screen.findAllByRole('row')
    // header row + 3 key rows
    expect(rows).toHaveLength(4)
    const revokedRow = rows.find(r => r.textContent?.includes('kid-revoked-1'))
    expect(revokedRow).toBeDefined()
    expect(revokedRow!.className).toContain('opacity-50')
  })

  it('hides the public card when the status endpoint has no data', () => {
    mockQuery.jwksStatus = undefined
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)
    expect(screen.queryByTestId('jwks-public-card')).not.toBeInTheDocument()
    // The table still renders.
    expect(screen.getByText('kid-active-1')).toBeInTheDocument()
  })

  it('opens the safeword dialog on Rotate click and does not POST immediately', async () => {
    const { api } = await import('../../lib/api')
    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)

    const rotateBtn = await screen.findByTestId('jwk-rotate-btn')
    fireEvent.click(rotateBtn)

    // The safeword dialog is open and on the confirm phase. The
    // destructive POST must NOT have fired yet.
    expect(screen.getByTestId('rotate-secret-dialog')).toBeInTheDocument()
    expect(screen.getByTestId('rotate-secret-generate')).toBeInTheDocument()
    expect(api.post).not.toHaveBeenCalled()
  })

  it('walks the full safeword handshake on Rotate', async () => {
    const { api } = await import('../../lib/api')
    // First call: challenge issuance
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      challenge_id: 'chal-xyz',
      word: 'correct-horse-purple-42',
      expires_at: '2099-01-01T00:00:00Z',
    })
    // Second call: destructive rotate
    ;(api.post as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      old_kid: 'kid-active-1',
      new_kid: 'kid-new-2',
    })

    render(<Wrapper><AdminJwkKeysPage /></Wrapper>)

    fireEvent.click(await screen.findByTestId('jwk-rotate-btn'))
    fireEvent.click(screen.getByTestId('rotate-secret-generate'))
    await screen.findByTestId('rotate-secret-safeword-phase')

    const input = screen.getByTestId('rotate-secret-input') as HTMLInputElement
    fireEvent.change(input, { target: { value: 'correct-horse-purple-42' } })
    fireEvent.click(screen.getByTestId('rotate-secret-confirm'))

    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        '/api/admin/jwk-keys/rotate/challenge'
      )
    })
    const rotateCall = (api.post as ReturnType<typeof vi.fn>).mock.calls.find(
      (c) => c[0] === '/api/admin/jwk-keys/rotate'
    )
    expect(rotateCall?.[1]).toEqual({
      challenge_id: 'chal-xyz',
      word: 'correct-horse-purple-42',
    })
  })
})

