// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { FederationLoginButtons } from './FederationLoginButtons'
import { API_URL } from '../../lib/constants'

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.get.mockResolvedValue([])
})

describe('FederationLoginButtons', () => {
  it('renders nothing while there are no providers', () => {
    const { container } = render(<FederationLoginButtons />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders a button per provider with a plain login URL', async () => {
    mockApi.get.mockResolvedValueOnce([
      { id: 'google', label: 'Google' },
      { id: 'github', label: 'GitHub', icon_uri: 'https://cdn.example/g.png' },
    ])
    render(<FederationLoginButtons context="dashboard" />)
    const link = await screen.findByTestId('fed-provider-google')
    const expected = new URLSearchParams()
    expected.set('redirect_uri', window.location.origin + window.location.pathname)
    expect(link.getAttribute('href')).toBe(
      `${API_URL}/api/federation/login/google?${expected.toString()}`,
    )
    expect(mockApi.get).toHaveBeenCalledWith('/api/federation/providers?context=dashboard')
    expect(screen.getByTestId('fed-provider-github').querySelector('img')).not.toBeNull()
  })

  it('forwards the OAuth2 context when provided', async () => {
    mockApi.get.mockResolvedValueOnce([{ id: 'sso', label: 'SSO' }])
    render(
      <FederationLoginButtons
        oauth2Context={{
          client_id: 'c1',
          oauth_redirect_uri: 'https://client.example/cb',
          scope: 'openid',
          app_state: 'st',
          code_challenge: 'chal',
          code_challenge_method: 'S256',
          response_type: 'code',
          oidc_nonce: 'nonce',
        }}
      />,
    )
    const link = await screen.findByTestId('fed-provider-sso')
    const href = link.getAttribute('href') as string
    expect(href).toContain('client_id=c1')
    expect(href).toContain('oauth_redirect_uri=https%3A%2F%2Fclient.example%2Fcb')
    expect(href).toContain('scope=openid')
    expect(href).toContain('app_state=st')
    expect(href).toContain('code_challenge=chal')
    expect(href).toContain('code_challenge_method=S256')
    expect(href).toContain('response_type=code')
    expect(href).toContain('oidc_nonce=nonce')
  })

  it('stays empty when the providers request fails', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('no federation'))
    const { container } = render(<FederationLoginButtons />)
    await waitFor(() => expect(mockApi.get).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
  })
})
