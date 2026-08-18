// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LoginForm } from '../../components/auth/LoginForm'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
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

vi.mock('../../lib/oauthCrypto', () => ({
  generateOAuthNonce: vi.fn(() => 'nonce'),
  generateOAuthState: vi.fn(() => 'state'),
  generatePkceChallenge: vi.fn(async () => 'challenge'),
  generatePkceVerifier: vi.fn(() => 'verifier'),
  PLAYGROUND_TRANSACTION_KEY: 'authglow-playground-transaction',
}))

import { api } from '../../lib/api'

const apiGetMock = api.get as ReturnType<typeof vi.fn>

function renderForm() {
  return render(
    <MemoryRouter>
      <LoginForm />
    </MemoryRouter>,
  )
}

describe('LoginForm demo mode', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('shows no demo banner when meta reports demo_mode=false', async () => {
    apiGetMock.mockResolvedValue({ demo_mode: false })
    renderForm()
    await waitFor(() => {
      expect(screen.queryByTestId('demo-mode-banner')).toBeNull()
    })
    expect(screen.queryByTestId('demo-credentials')).toBeNull()
  })

  it('shows demo banner and credentials when demo_mode=true', async () => {
    apiGetMock.mockResolvedValue({
      demo_mode: true,
      demo_banner_text: 'Demo environment — data resets on restart.',
      demo_user_email: 'admin@example.com',
      demo_user_password: 'boot-pass',
    })
    renderForm()
    await waitFor(() => {
      expect(screen.getByTestId('demo-mode-banner')).toBeInTheDocument()
    })
    expect(screen.getByText(/data resets on restart/)).toBeInTheDocument()
    const creds = screen.getByTestId('demo-credentials')
    expect(creds).toHaveTextContent('admin@example.com')
    expect(creds).toHaveTextContent('boot-pass')
  })

  it('hides credentials box when meta lacks the password', async () => {
    apiGetMock.mockResolvedValue({
      demo_mode: true,
      demo_banner_text: 'Demo.',
      demo_user_email: 'admin@example.com',
      demo_user_password: '',
    })
    renderForm()
    await waitFor(() => {
      expect(screen.getByTestId('demo-mode-banner')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('demo-credentials')).toBeNull()
  })
})