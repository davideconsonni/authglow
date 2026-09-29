// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { DashboardPage } from './DashboardPage'
import { ROUTES } from '../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
const mockAuth = vi.hoisted(() => ({ user: null as Record<string, unknown> | null }))
const mockData = vi.hoisted(() => ({
  profile: undefined as Record<string, unknown> | undefined,
  sessions: undefined as Record<string, unknown> | undefined,
  keys: undefined as unknown[] | undefined,
  stats: undefined as Record<string, unknown> | undefined,
}))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

vi.mock('../hooks/useAuth', () => ({ useAuth: () => ({ user: mockAuth.user }) }))

vi.mock('../hooks/useApi', () => ({
  useApiQuery: (key: string[]) => {
    if (key[0] === 'profile-me') return { data: mockData.profile }
    if (key[0] === 'my-dash-sessions') return { data: mockData.sessions }
    if (key[0] === 'my-dash-keys') return { data: mockData.keys }
    if (key[0] === 'dash-stats-v2') return { data: mockData.stats }
    return { data: undefined }
  },
}))

vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

const PROFILE = {
  id: 'u-1',
  email: 'ada@example.com',
  email_verified: true,
  first_name: 'Ada',
  last_name: 'Lovelace',
  mfa_enabled: true,
  created_at: '2025-01-01T00:00:00Z',
  last_login: '2026-09-01T00:00:00Z',
  roles: [],
  scopes: ['read'],
}

function baseData() {
  mockData.profile = { ...PROFILE }
  mockData.sessions = { sessions: [], total: 0 }
  mockData.keys = []
  mockData.stats = { total_users: 0 }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.user = {
    is_admin: false,
    permissions: [],
    is_federated: false,
    email_verified: true,
    mfa_enabled: true,
    first_name: 'Ada',
    last_name: 'Lovelace',
    email: 'ada@example.com',
  }
  baseData()
})

describe('DashboardPage — loading', () => {
  it('renders the skeleton until the first query resolves', () => {
    mockData.profile = undefined
    mockData.sessions = undefined
    mockData.keys = undefined
    const { container } = render(<DashboardPage />)
    expect(container.querySelector('.animate-pulse')).not.toBeNull()
    expect(screen.queryByText(/Welcome back/)).not.toBeInTheDocument()
  })
})

describe('DashboardPage — identity', () => {
  it('greets the user and shows the identity card', () => {
    render(<DashboardPage />)
    expect(screen.getByText('Welcome back, Ada')).toBeInTheDocument()
    expect(screen.getByText('ada@example.com')).toBeInTheDocument()
    expect(screen.getByText('Email verified')).toBeInTheDocument()
    expect(screen.getByText('MFA enabled')).toBeInTheDocument()
  })

  it('falls back to "User" and placeholders when auth user is missing', () => {
    mockAuth.user = null
    render(<DashboardPage />)
    expect(screen.getByText('Welcome back, Ada')).toBeInTheDocument()
  })

  it('shows the provider-managed badge and hides quick actions when federated', () => {
    mockAuth.user = { is_federated: true, permissions: [], email_verified: true, mfa_enabled: true }
    render(<DashboardPage />)
    expect(screen.getByText('Provider managed')).toBeInTheDocument()
    expect(
      screen.getByText('Email and MFA are managed by your identity provider.'),
    ).toBeInTheDocument()
    expect(screen.queryByText('Quick Actions')).not.toBeInTheDocument()
  })

  it('renders placeholders when the profile is absent', () => {
    mockData.profile = undefined
    mockAuth.user = null
    render(<DashboardPage />)
    expect(screen.getByText('Welcome back, User')).toBeInTheDocument()
    expect(screen.getAllByText('-').length).toBeGreaterThan(0)
  })
})

describe('DashboardPage — security section', () => {
  it('shows the all-clear when verified', () => {
    render(<DashboardPage />)
    expect(screen.getByText('All security recommendations completed.')).toBeInTheDocument()
  })

  it('shows the checklist and navigates from each item', () => {
    mockAuth.user = {
      is_admin: false,
      permissions: [],
      is_federated: false,
      email_verified: false,
      mfa_enabled: false,
    }
    mockData.profile = { ...PROFILE, email_verified: false, mfa_enabled: false }
    render(<DashboardPage />)
    fireEvent.click(screen.getByText('Verify your email'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.PROFILE)
    fireEvent.click(screen.getByText('Enable two-factor authentication'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SECURITY)
  })
})

describe('DashboardPage — quick actions', () => {
  it('navigates from each quick action', () => {
    render(<DashboardPage />)
    fireEvent.click(screen.getByText('Change Password'))
    fireEvent.click(screen.getByText('Setup MFA'))
    fireEvent.click(screen.getByText('Create API Key'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SECURITY)
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.API_KEYS)
  })
})

describe('DashboardPage — at a glance', () => {
  it('renders singular counts and navigates', () => {
    mockData.sessions = { sessions: [{}], total: 1 }
    mockData.keys = [{}]
    render(<DashboardPage />)
    expect(screen.getByText('1 device')).toBeInTheDocument()
    expect(screen.getByText('1 key')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Active sessions'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.SESSIONS)
    fireEvent.click(screen.getByText('API keys'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.API_KEYS)
  })

  it('renders plural counts', () => {
    mockData.sessions = { sessions: [{}, {}, {}], total: 3 }
    mockData.keys = []
    render(<DashboardPage />)
    expect(screen.getByText('3 devices')).toBeInTheDocument()
    expect(screen.getByText('0 keys active')).toBeInTheDocument()
  })
})

describe('DashboardPage — admin stats', () => {
  it('shows the stats card and administration panel for an admin', () => {
    mockAuth.user = {
      is_admin: true,
      permissions: [],
      is_federated: false,
      email_verified: true,
      mfa_enabled: true,
    }
    mockData.stats = { total_users: 42 }
    render(<DashboardPage />)
    expect(screen.getByText('Total users')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('Open admin overview')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Total users'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.USERS)
    fireEvent.click(screen.getByText('Open admin overview'))
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.ADMIN.DASHBOARD)
  })

  it('shows admin stats to a view-only admin.read operator', () => {
    mockAuth.user = {
      is_admin: false,
      permissions: ['admin.read'],
      is_federated: false,
      email_verified: true,
      mfa_enabled: true,
    }
    render(<DashboardPage />)
    expect(screen.getByText('Total users')).toBeInTheDocument()
  })

  it('hides admin stats without admin capability', () => {
    render(<DashboardPage />)
    expect(screen.queryByText('Total users')).not.toBeInTheDocument()
    expect(screen.queryByText('Open admin overview')).not.toBeInTheDocument()
  })
})
