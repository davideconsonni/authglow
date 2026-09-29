// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { AdminDashboardPage } from './AdminDashboardPage'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
const mockData = vi.hoisted(() => ({
  stats: undefined as Record<string, unknown> | undefined,
  recent: undefined as unknown,
  loading: false,
}))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('../../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'admin-stats-v2') return { data: mockData.stats, isLoading: mockData.loading }
    return { data: mockData.recent, isLoading: false }
  },
}))

vi.mock('../../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

const STATS = {
  total_users: 120,
  active_users: 100,
  inactive_users: 20,
  users_with_mfa: 60,
  mfa_percentage: 50,
  new_users_today: 3,
  new_users_this_week: 12,
  new_users_this_month: 40,
}

beforeEach(() => {
  vi.clearAllMocks()
  mockData.stats = STATS
  mockData.recent = { items: [] }
  mockData.loading = false
})

describe('AdminDashboardPage', () => {
  it('shows the loading spinner', () => {
    mockData.loading = true
    render(<AdminDashboardPage />)
    expect(screen.queryByText('Administration')).not.toBeInTheDocument()
  })

  it('renders the stats, quick badges, and navigation targets', () => {
    mockData.recent = {
      items: [
        { id: 'u1', email: 'a@example.com', first_name: 'Ada', last_name: 'L', created_at: '2026-09-01T00:00:00Z' },
        { id: 'u2', email: 'b@example.com', created_at: '2026-09-02T00:00:00Z' },
      ],
    }
    render(<AdminDashboardPage />)
    expect(screen.getByText('120')).toBeInTheDocument()
    expect(screen.getByText('50%')).toBeInTheDocument()
    expect(screen.getByText('+3 today')).toBeInTheDocument()
    expect(screen.getByText('Ada L')).toBeInTheDocument()
    expect(screen.getAllByText('b@example.com').length).toBeGreaterThan(0)

    fireEvent.click(screen.getByText('Total Users'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.USERS)
    fireEvent.click(screen.getByText('MFA Adoption'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.USERS)
    fireEvent.click(screen.getByText('New Users (30d)'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.SESSIONS)
    fireEvent.click(screen.getByText('Manage accounts'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.USERS)
    fireEvent.click(screen.getByText('Registered clients'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.OAUTH_CLIENTS)
    fireEvent.click(screen.getByText('Active tokens'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.SESSIONS)
    fireEvent.click(screen.getByText('Roles & permissions'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.RBAC)
  })

  it('accepts a bare array of recent users', () => {
    mockData.recent = [
      { id: 'u1', email: 'a@example.com', first_name: 'Ada', last_name: 'L', created_at: '2026-09-01T00:00:00Z' },
    ]
    render(<AdminDashboardPage />)
    expect(screen.getByText('Ada L')).toBeInTheDocument()
  })

  it('shows the empty recent-users state', () => {
    render(<AdminDashboardPage />)
    expect(screen.getByText('No recent users')).toBeInTheDocument()
  })
})
