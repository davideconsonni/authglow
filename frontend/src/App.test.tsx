// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import App from './App'

const authState = vi.hoisted(() => ({
  _hydrated: true,
  isAuthenticated: false,
  user: null as unknown,
  isLoading: false,
  logout: vi.fn(),
  setAuthenticated: vi.fn(),
  setUser: vi.fn(),
  fetchCurrentUser: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('./stores/authStore', () => ({
  useAuthStore: Object.assign(
    (selector?: (s: typeof authState) => unknown) => (selector ? selector(authState) : authState),
    { getState: () => authState },
  ),
}))

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('./lib/api', () => ({ api: mockApi, ApiError: class extends Error {} }))
vi.mock('./hooks/useTheme', () => ({ useTheme: () => ({}) }))

vi.mock('./components/layout/AppShell', async () => {
  const { Outlet } = await import('react-router-dom')
  return {
    AppShell: () => (
      <div data-testid="app-shell">
        <Outlet />
      </div>
    ),
  }
})
vi.mock('./components/shared/LoadingState', () => ({ LoadingState: () => <div data-testid="loading" /> }))
vi.mock('./components/shared/Toast', () => ({ ToastContainer: () => null }))
vi.mock('./components/admin/CommandPalette', () => ({ CommandPalette: () => null }))

vi.mock('./pages/auth/LoginPage', () => ({ LoginPage: () => <div data-testid="page-login" /> }))
vi.mock('./pages/DashboardPage', () => ({ DashboardPage: () => <div data-testid="page-dashboard" /> }))
vi.mock('./pages/SetupPage', () => ({ SetupPage: () => <div data-testid="page-setup" /> }))
vi.mock('./pages/NotFoundPage', () => ({ NotFoundPage: () => <div data-testid="page-notfound" /> }))

vi.mock('./pages/SecurityPage', () => ({ SecurityPage: () => <div data-testid="page-security" /> }))
vi.mock('./pages/admin/AdminDashboardPage', () => ({ AdminDashboardPage: () => <div data-testid="page-admin-dashboard" /> }))
vi.mock('./pages/admin/AdminUsersPage', () => ({ AdminUsersPage: () => <div data-testid="page-admin-users" /> }))
vi.mock('./pages/admin/AdminOAuthClientsPage', () => ({ AdminOAuthClientsPage: () => <div data-testid="page-admin-clients" /> }))
vi.mock('./pages/admin/AdminSessionsPage', () => ({ AdminSessionsPage: () => <div data-testid="page-admin-sessions" /> }))
vi.mock('./pages/admin/AdminConsentsPage', () => ({ AdminConsentsPage: () => <div data-testid="page-admin-consents" /> }))
vi.mock('./pages/admin/AdminApiKeysPage', () => ({ AdminApiKeysPage: () => <div data-testid="page-admin-apikeys" /> }))
vi.mock('./pages/admin/AdminRbacPage', () => ({ AdminRbacPage: () => <div data-testid="page-admin-rbac" /> }))
vi.mock('./pages/admin/AdminJwkKeysPage', () => ({ AdminJwkKeysPage: () => <div data-testid="page-admin-jwk" /> }))
vi.mock('./pages/admin/AdminPasswordResetsPage', () => ({ AdminPasswordResetsPage: () => <div data-testid="page-admin-resets" /> }))
vi.mock('./pages/admin/AdminPlaygroundPage', () => ({ AdminPlaygroundPage: () => <div data-testid="page-admin-playground" /> }))
vi.mock('./pages/admin/AdminFederationPage', () => ({ AdminFederationPage: () => <div data-testid="page-admin-federation" /> }))
vi.mock('./pages/admin/AdminSettingsPage', () => ({ AdminSettingsPage: () => <div data-testid="page-admin-settings" /> }))
vi.mock('./pages/admin/AdminRateLimitsPage', () => ({ AdminRateLimitsPage: () => <div data-testid="page-admin-ratelimits" /> }))
vi.mock('./pages/admin/AdminWebhooksPage', () => ({ AdminWebhooksPage: () => <div data-testid="page-admin-webhooks" /> }))
vi.mock('./pages/admin/DeviceAuthNewTool', () => ({ DeviceAuthNewTool: () => <div data-testid="page-device-new" /> }))
vi.mock('./pages/admin/AdminDeviceAuthsPage', () => ({ AdminDeviceAuthsPage: () => <div data-testid="page-admin-deviceauths" /> }))

import { ROUTES } from './lib/constants'

function goto(path: string) {
  window.history.pushState({}, '', path)
}

beforeEach(() => {
  vi.clearAllMocks()
  authState._hydrated = true
  authState.isAuthenticated = false
  authState.fetchCurrentUser = vi.fn().mockResolvedValue(undefined)
  mockApi.get.mockResolvedValue({ needs_setup: false })
  goto('/')
})

describe('App routing and guards', () => {
  it('renders the login page for guests', async () => {
    goto('/auth/login')
    render(<App />)
    expect(await screen.findByTestId('page-login')).toBeInTheDocument()
  })

  it('redirects an authenticated guest to the dashboard', async () => {
    authState.isAuthenticated = true
    goto('/auth/login')
    render(<App />)
    expect(await screen.findByTestId('app-shell')).toBeInTheDocument()
  })

  it('shows a loading state while the auth store hydrates', () => {
    authState._hydrated = false
    goto('/dashboard')
    render(<App />)
    expect(screen.getByTestId('loading')).toBeInTheDocument()
  })

  it('redirects an unauthenticated protected route to login', async () => {
    goto('/dashboard')
    render(<App />)
    expect(await screen.findByTestId('page-login')).toBeInTheDocument()
  })

  it('renders the setup page directly at /setup', async () => {
    goto('/setup')
    render(<App />)
    expect(await screen.findByTestId('page-setup')).toBeInTheDocument()
    expect(mockApi.get).not.toHaveBeenCalled()
  })

  it('redirects to setup when the server needs setup', async () => {
    mockApi.get.mockResolvedValueOnce({ needs_setup: true })
    goto('/auth/login')
    render(<App />)
    expect(await screen.findByTestId('page-setup')).toBeInTheDocument()
  })

  it('redirects the root to the dashboard', async () => {
    authState.isAuthenticated = true
    goto('/')
    render(<App />)
    expect(await screen.findByTestId('app-shell')).toBeInTheDocument()
  })

  it('renders the not-found page for an unknown path', async () => {
    goto('/definitely-missing')
    render(<App />)
    expect(await screen.findByTestId('page-notfound')).toBeInTheDocument()
  })

  it('propagates the setup-check failure as not-needed', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('down'))
    goto('/auth/login')
    render(<App />)
    expect(await screen.findByTestId('page-login')).toBeInTheDocument()
  })
})

const LAZY_ROUTES: Array<[string, string]> = [
  [ROUTES.SECURITY, 'page-security'],
  [ROUTES.ADMIN.DASHBOARD, 'page-admin-dashboard'],
  [ROUTES.ADMIN.USERS, 'page-admin-users'],
  [ROUTES.ADMIN.OAUTH_CLIENTS, 'page-admin-clients'],
  [ROUTES.ADMIN.SESSIONS, 'page-admin-sessions'],
  [ROUTES.ADMIN.CONSENTS, 'page-admin-consents'],
  [ROUTES.ADMIN.API_KEYS, 'page-admin-apikeys'],
  [ROUTES.ADMIN.RBAC, 'page-admin-rbac'],
  [ROUTES.ADMIN.JWK_KEYS, 'page-admin-jwk'],
  [ROUTES.ADMIN.PASSWORD_RESETS, 'page-admin-resets'],
  [ROUTES.ADMIN.PLAYGROUND, 'page-admin-playground'],
  [ROUTES.ADMIN.FEDERATION, 'page-admin-federation'],
  [ROUTES.ADMIN.SETTINGS, 'page-admin-settings'],
  [ROUTES.ADMIN.RATE_LIMITS, 'page-admin-ratelimits'],
  [ROUTES.ADMIN.WEBHOOKS, 'page-admin-webhooks'],
  [ROUTES.ADMIN.DEVICE_AUTHORIZATIONS_NEW, 'page-device-new'],
  [ROUTES.ADMIN.DEVICE_AUTHORIZATIONS, 'page-admin-deviceauths'],
]

describe('App lazy routes', () => {
  for (const [route, testid] of LAZY_ROUTES) {
    it(`renders the lazy page at ${route}`, async () => {
      authState.isAuthenticated = true
      goto(route)
      render(<App />)
      expect(await screen.findByTestId(testid)).toBeInTheDocument()
    })
  }
})

describe('ProtectedRoute lifecycle', () => {  it('clears the session and revalidates on lifecycle events', async () => {
    authState.isAuthenticated = true
    goto('/dashboard')
    render(<App />)
    await screen.findByTestId('app-shell')

    window.dispatchEvent(new Event('auth:session-expired'))
    expect(authState.setAuthenticated).toHaveBeenCalledWith(false)

    window.dispatchEvent(new StorageEvent('storage', { key: 'auth-state-event', newValue: '1' }))
    expect(authState.setAuthenticated).toHaveBeenCalledTimes(2)

    window.dispatchEvent(new Event('focus'))
    document.dispatchEvent(new Event('visibilitychange'))
    await waitFor(() => expect(authState.fetchCurrentUser).toHaveBeenCalled())
  })
})
