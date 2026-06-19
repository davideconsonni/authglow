// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { LoginPage } from '@/pages/auth/LoginPage'

vi.mock('@/lib/api', () => ({
  api: {
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

vi.mock('@/components/auth/LoginForm', () => ({
  LoginForm: () => <div data-testid="login-form">LoginForm</div>,
}))

vi.mock('@/components/auth/PasskeyLoginButton', () => ({
  PasskeyLoginButton: () => <div data-testid="passkey-btn">Passkey</div>,
}))

vi.mock('@/components/auth/FederationLoginButtons', () => ({
  FederationLoginButtons: () => <div data-testid="federation-btns">Federation</div>,
}))

vi.mock('@/hooks/useDocumentTitle', () => ({
  useDocumentTitle: vi.fn(),
}))

import { api } from '@/lib/api'

const apiPostMock = api.post as ReturnType<typeof vi.fn>

function renderPage(state?: Record<string, unknown>) {
  return render(
    <MemoryRouter
      initialEntries={[
        { pathname: '/auth/login', state },
      ]}
    >
      <LoginPage />
    </MemoryRouter>,
  )
}

describe('LoginPage resend verification', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('does not show registration banner when state is empty', () => {
    renderPage()
    expect(screen.queryByText(/Account created/)).toBeNull()
  })

  it('shows registration banner when registered state is true', () => {
    renderPage({ registered: true })
    expect(screen.getByText(/Account created/)).toBeInTheDocument()
  })

  it('does not show resend button when email is missing from state', () => {
    renderPage({ registered: true })
    expect(screen.queryByText(/Didn't receive the email/)).toBeNull()
  })

  it('shows resend button when email is in state', () => {
    renderPage({ registered: true, email: 'new@example.com' })
    expect(screen.getByText(/Didn't receive the email/)).toBeInTheDocument()
  })

  it('sends resend request with email on click', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage({ registered: true, email: 'new@example.com' })
    const btn = screen.getByText(/Didn't receive the email/)
    fireEvent.click(btn)
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/api/email/resend-verification', {
        email: 'new@example.com',
      })
    })
  })

  it('shows success message after resend', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage({ registered: true, email: 'new@example.com' })
    const btn = screen.getByText(/Didn't receive the email/)
    fireEvent.click(btn)
    await waitFor(() => {
      expect(screen.getByText(/Verification email resent/)).toBeInTheDocument()
    })
  })
})
