// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { SessionsPage } from './SessionsPage'

const mockQuery = vi.hoisted(() => ({
  sessions: [] as unknown,
  myToken: undefined as { access_token?: string } | undefined,
}))

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}))

vi.mock('../hooks/useApi', () => ({
  useApiQuery: (_key: string[], endpoint: string) => {
    if (endpoint === '/api/tokens/refresh/list') {
      return { data: mockQuery.sessions, refetch: vi.fn(), isLoading: false }
    }
    if (endpoint === '/api/auth/my-token') {
      return { data: mockQuery.myToken, refetch: vi.fn(), isLoading: false }
    }
    return { data: undefined, refetch: vi.fn(), isLoading: false }
  },
}))

vi.mock('../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn() },
}))

function makeJwt(payload: Record<string, unknown>): string {
  const b64url = (s: string) =>
    btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${b64url('{"alg":"RS256","typ":"JWT"')}.${b64url(JSON.stringify(payload))}.sig`
}

const SESSIONS = [
  {
    id: 's1',
    client: 'Chrome / Windows',
    ip_address: '10.0.0.2',
    created_at: '2026-08-25T08:00:00Z',
    last_active: '2026-08-25T16:00:00Z',
  },
]

describe('SessionsPage - my token section (Fase 6)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockQuery.sessions = SESSIONS
    mockQuery.myToken = {
      access_token: makeJwt({
        sub: 'user-1',
        email: 'demo@example.com',
        scope: 'read write',
        exp: 1790000000,
      }),
    }
  })

  it('starts collapsed — no panel until toggled', () => {
    render(<SessionsPage />)
    expect(screen.queryByTestId('my-token-panel')).not.toBeInTheDocument()
    expect(screen.getByTestId('my-token-toggle')).toHaveAttribute('aria-expanded', 'false')
  })

  it('shows the decoded claims when expanded', () => {
    render(<SessionsPage />)
    fireEvent.click(screen.getByTestId('my-token-toggle'))
    const panel = screen.getByTestId('my-token-panel')
    expect(panel.textContent).toContain('demo@example.com')
    expect(panel.textContent).toContain('user-1')
    expect(screen.getByTestId('my-token-toggle')).toHaveAttribute('aria-expanded', 'true')
  })

  it('hides the panel again on second click', () => {
    render(<SessionsPage />)
    fireEvent.click(screen.getByTestId('my-token-toggle'))
    fireEvent.click(screen.getByTestId('my-token-toggle'))
    expect(screen.queryByTestId('my-token-panel')).not.toBeInTheDocument()
  })

  it('shows a placeholder when there is no active access token', () => {
    mockQuery.myToken = { access_token: '' }
    render(<SessionsPage />)
    fireEvent.click(screen.getByTestId('my-token-toggle'))
    expect(screen.getByText('No active access token.')).toBeInTheDocument()
  })
})
