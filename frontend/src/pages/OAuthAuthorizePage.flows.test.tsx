// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { OAuthAuthorizePage } from './OAuthAuthorizePage'
import { ROUTES } from '../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ get: vi.fn(), postForm: vi.fn(), post: vi.fn() }))
vi.mock('../lib/api', () => ({ api: mockApi }))

const mockAuth = vi.hoisted(() => ({ isAuthenticated: false }))
vi.mock('../hooks/useAuth', () => ({ useAuth: () => ({ isAuthenticated: mockAuth.isAuthenticated }) }))

const mockDemo = vi.hoisted(() => ({ meta: { demo_mode: false } as Record<string, unknown> }))
vi.mock('../hooks/useDemoMeta', () => ({ useDemoMeta: () => ({ meta: mockDemo.meta }) }))

vi.mock('../components/oauth/ConsentScreen', () => ({
  ConsentScreen: ({ clientName, sessionToken }: { clientName: string; sessionToken: string }) => (
    <div data-testid="consent-screen">
      {clientName}|{sessionToken}
    </div>
  ),
}))
vi.mock('../components/auth/FederationLoginButtons', () => ({ FederationLoginButtons: () => null }))
vi.mock('../components/auth/PasskeyLoginButton', () => ({ PasskeyLoginButton: () => null }))
vi.mock('../components/shared/ThemeSwitcher', () => ({ ThemeSwitcher: () => null }))

const CLIENT_INFO = { client_name: 'My App', client_description: 'Does things' }
const CONSENT_DATA = {
  consent_required: true,
  session_token: 'SESSION-1',
  client_name: 'My App',
  scopes: [{ name: 'read', description: 'Read' }],
}

const BASE = 'client_id=c1&redirect_uri=https%3A%2F%2Fapp%2Fcb&scope=read&state=st&code_challenge=ch&code_challenge_method=S256&nonce=n'

function renderPage(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <OAuthAuthorizePage />
    </MemoryRouter>,
  )
}

function fillCredentials() {
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'u@example.com' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'pw' } })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.isAuthenticated = false
  mockDemo.meta = { demo_mode: false }
  sessionStorage.clear()
  Object.defineProperty(window, 'location', { value: { href: '' }, writable: true, configurable: true })
  mockApi.get.mockResolvedValue(CLIENT_INFO)
  mockApi.postForm.mockResolvedValue({})
})

describe('OAuthAuthorizePage — parameter handling', () => {
  it('reports missing parameters', async () => {
    renderPage('/oauth2/authorize')
    expect(
      await screen.findByText('Missing required parameters (client_id and redirect_uri).'),
    ).toBeInTheDocument()
  })

  it('allows the federated shortcut without client params', async () => {
    renderPage('/oauth2/authorize?fed=1')
    expect(await screen.findByText('Sign in to AuthGlow')).toBeInTheDocument()
  })

  it('rejects an unsupported response_type', async () => {
    renderPage(`/oauth2/authorize?${BASE}&response_type=token`)
    expect(
      await screen.findByText('Unsupported response_type. Only "code" is supported.'),
    ).toBeInTheDocument()
  })

  it('reports an invalid client', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('nope'))
    renderPage(`/oauth2/authorize?${BASE}`)
    expect(
      await screen.findByText('Invalid client_id or the application is not active.'),
    ).toBeInTheDocument()
  })
})

describe('OAuthAuthorizePage — client branding', () => {
  it('renders the client logo when provided', async () => {
    mockApi.get.mockResolvedValueOnce({ ...CLIENT_INFO, client_logo_uri: 'https://x/logo.png' })
    renderPage(`/oauth2/authorize?${BASE}`)
    expect(await screen.findByAltText('My App logo')).toBeInTheDocument()
  })

  it('renders the shield icon without a logo', async () => {
    renderPage(`/oauth2/authorize?${BASE}`)
    expect(await screen.findByText('My App')).toBeInTheDocument()
    expect(screen.queryByAltText('My App logo')).not.toBeInTheDocument()
  })
})

describe('OAuthAuthorizePage — login', () => {
  it('signs in and follows the redirect_url', async () => {
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/authorize' ? { redirect_url: 'https://app/cb?code=x' } : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    await waitFor(() => expect(window.location.href).toBe('https://app/cb?code=x'))
    const body = mockApi.postForm.mock.calls.find((c) => c[0] === '/api/oauth2/authorize')![1]
    expect(body).toMatchObject({ code_challenge: 'ch', code_challenge_method: 'S256', nonce: 'n' })
  })

  it('moves to the consent screen when consent is required', async () => {
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/authorize' ? CONSENT_DATA : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    expect(await screen.findByTestId('consent-screen')).toHaveTextContent('My App|SESSION-1')
  })

  it('routes to MFA verification when required', async () => {
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/authorize' ? { mfa_required: 'totp', session_token: 'sess' } : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    await waitFor(() =>
      expect(window.location.href).toBe('/auth/mfa-verify?session_token=sess&oauth=1'),
    )
  })

  it('routes an expired password to the change screen', async () => {
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/authorize' ? { password_expired: true } : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    await waitFor(() =>
      expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.PASSWORD_EXPIRED, {
        state: { email: 'u@example.com' },
      }),
    )
  })

  it('maps an invalid-credentials error', async () => {
    mockApi.postForm.mockImplementation(async (url: string) => {
      if (url === '/api/oauth2/authorize') throw new Error('Invalid credentials provided')
      return {}
    })
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    expect(await screen.findByText('Invalid email or password.')).toBeInTheDocument()
  })

  it('maps a locked-account error', async () => {
    mockApi.postForm.mockImplementation(async (url: string) => {
      if (url === '/api/oauth2/authorize') throw new Error('Account locked')
      return {}
    })
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    expect(
      await screen.findByText('Account is temporarily locked. Try again later.'),
    ).toBeInTheDocument()
  })

  it('shows a generic login error', async () => {
    mockApi.postForm.mockImplementation(async (url: string) => {
      if (url === '/api/oauth2/authorize') throw new Error('server exploded')
      return {}
    })
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    fillCredentials()
    fireEvent.click(screen.getByText('Sign In & Continue'))
    expect(await screen.findByText('server exploded')).toBeInTheDocument()
  })
})

describe('OAuthAuthorizePage — demo mode', () => {
  it('shows the demo credentials and fills them on click and keyboard', async () => {
    mockDemo.meta = {
      demo_mode: true,
      demo_banner_text: 'Demo notice',
      demo_user_email: 'demo@authglow.io',
      demo_user_password: 'demo-pass',
    }
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    expect(screen.getByText('Demo notice')).toBeInTheDocument()
    const box = await screen.findByTestId('demo-credentials')
    fireEvent.click(box)
    expect(screen.getByLabelText('Email')).toHaveValue('demo@authglow.io')
    expect(screen.getByLabelText('Password')).toHaveValue('demo-pass')

    fireEvent.change(screen.getByLabelText('Email'), { target: { value: '' } })
    fireEvent.keyDown(box, { key: 'Enter' })
    expect(screen.getByLabelText('Email')).toHaveValue('demo@authglow.io')
  })

  it('prefills the email from sessionStorage in demo mode', async () => {
    sessionStorage.setItem('authglow_demo_email', 'pre@x.io')
    mockDemo.meta = { demo_mode: true }
    renderPage(`/oauth2/authorize?${BASE}`)
    await screen.findByText('Sign in to AuthGlow')
    await waitFor(() => expect(screen.getByLabelText('Email')).toHaveValue('pre@x.io'))
  })
})

describe('OAuthAuthorizePage — authenticated and federated flows', () => {
  it('completes authorization for an authenticated passkey session', async () => {
    mockAuth.isAuthenticated = true
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/authorize' ? { redirect_url: 'https://done' } : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    await waitFor(() => expect(window.location.href).toBe('https://done'))
  })

  it('surfaces a passkey authorization failure', async () => {
    mockAuth.isAuthenticated = true
    mockApi.postForm.mockImplementation(async (url: string) => {
      if (url === '/api/oauth2/authorize') throw new Error('passkey boom')
      return {}
    })
    renderPage(`/oauth2/authorize?${BASE}`)
    expect(await screen.findByText('passkey boom')).toBeInTheDocument()
  })

  it('switches to consent when a federated session is pending', async () => {
    mockApi.postForm.mockImplementation(async (url: string) =>
      url === '/api/oauth2/federated-consent' ? CONSENT_DATA : {},
    )
    renderPage(`/oauth2/authorize?${BASE}`)
    expect(await screen.findByTestId('consent-screen')).toHaveTextContent('My App|SESSION-1')
  })
})
