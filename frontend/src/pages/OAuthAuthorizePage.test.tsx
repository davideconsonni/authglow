// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { OAuthAuthorizePage } from './OAuthAuthorizePage'

vi.mock('../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ demo_mode: false }),
    post: vi.fn(),
    postForm: vi.fn(),
  },
  ApiError: class extends Error {
    status: number
    data: unknown
    constructor(status: number, data: unknown) {
      super(String(data))
      this.status = status
      this.data = data
    }
  },
}))

vi.mock('../components/auth/FederationLoginButtons', () => ({
  FederationLoginButtons: () => null,
}))

vi.mock('../components/auth/PasskeyLoginButton', () => ({
  PasskeyLoginButton: () => null,
}))

import { api } from '../lib/api'

const apiGetMock = api.get as ReturnType<typeof vi.fn>
const apiPostFormMock = api.postForm as ReturnType<typeof vi.fn>

function renderPage(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <OAuthAuthorizePage />
    </MemoryRouter>,
  )
}

const CONSENT_DATA = {
  consent_required: true,
  session_token: 'SECRET-TOKEN',
  redirect_uri: 'https://client.example/callback',
  client_id: 'client-1',
  client_name: 'Test client',
  scopes: [{ name: 'openid', description: 'Verify your identity' }],
}

describe('OAuthAuthorizePage consent check transport (ZAP-006)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('sends session_token in POST body, never in the URL', async () => {
    apiPostFormMock.mockResolvedValueOnce(CONSENT_DATA)
    renderPage('/oauth2/authorize?mfa_session_token=SECRET-TOKEN')

    await waitFor(() => {
      expect(apiPostFormMock).toHaveBeenCalledWith('/api/oauth2/consent/check', {
        session_token: 'SECRET-TOKEN',
      })
    })

    for (const [url] of apiPostFormMock.mock.calls) {
      expect(url).not.toContain('?')
      expect(url).not.toContain('session_token=')
    }
    expect(apiGetMock).not.toHaveBeenCalledWith(
      expect.stringContaining('consent/check'),
      expect.anything(),
    )
  })

  it('shows the consent screen after the POST check', async () => {
    apiPostFormMock.mockResolvedValueOnce(CONSENT_DATA)
    renderPage('/oauth2/authorize?mfa_session_token=SECRET-TOKEN')

    await waitFor(() => {
      expect(screen.getByText('Test client')).toBeInTheDocument()
    })
  })

  it('shows the expired-session error when the POST check fails', async () => {
    apiPostFormMock.mockRejectedValueOnce(new Error('gone'))
    renderPage('/oauth2/authorize?mfa_session_token=STALE-TOKEN')

    await waitFor(() => {
      expect(
        screen.getByText('The OAuth authorization session has expired.'),
      ).toBeInTheDocument()
    })
  })
})
