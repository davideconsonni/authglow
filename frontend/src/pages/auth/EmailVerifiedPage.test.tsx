// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { EmailVerifiedPage } from '@/pages/auth/EmailVerifiedPage'

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

import { api } from '@/lib/api'

const apiPostMock = api.post as ReturnType<typeof vi.fn>

function renderPage(route = '/auth/verify-email') {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <EmailVerifiedPage />
    </MemoryRouter>,
  )
}

describe('EmailVerifiedPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the verification form when no token in URL', () => {
    renderPage()
    expect(screen.getByText('Verify your email')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('XXXX-XXXX-XXXX')).toBeInTheDocument()
  })

  it('shows resend button in the form', () => {
    renderPage()
    expect(screen.getByText('Resend verification email')).toBeInTheDocument()
  })

  it('sends email in body when resend is clicked with email query param', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage('/auth/verify-email?email=test@example.com')
    const btn = screen.getByText('Resend verification email')
    fireEvent.click(btn)
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/api/email/resend-verification', {
        email: 'test@example.com',
      })
    })
  })

  it('sends empty body when resend is clicked without email param', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage()
    const btn = screen.getByText('Resend verification email')
    fireEvent.click(btn)
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/api/email/resend-verification', undefined)
    })
  })

  it('shows success message after resend', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage()
    const btn = screen.getByText('Resend verification email')
    fireEvent.click(btn)
    await waitFor(() => {
      expect(screen.getByText('Verification email sent. Check your inbox.')).toBeInTheDocument()
    })
  })

  it('keeps resend button on API failure', async () => {
    apiPostMock.mockRejectedValueOnce(new Error('fail'))
    renderPage()
    const btn = screen.getByText('Resend verification email')
    fireEvent.click(btn)
    await waitFor(() => {
      expect(screen.getByText('Resend verification email')).toBeInTheDocument()
    })
  })

  it('verifies email with token from URL on mount', async () => {
    apiPostMock.mockResolvedValueOnce({})
    renderPage('/auth/verify-email?token=ABCD-EFGH-JKLM')
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/api/email/verify', {
        token: 'ABCD-EFGH-JKLM',
      })
    })
  })
})
