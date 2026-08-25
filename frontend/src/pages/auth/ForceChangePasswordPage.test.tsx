// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ForceChangePasswordPage } from './ForceChangePasswordPage'

vi.mock('../../lib/api', () => ({
  api: {
    get: vi.fn().mockResolvedValue({ demo_mode: false }),
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

vi.mock('../../stores/toastStore', () => ({
  notify: { success: vi.fn(), error: vi.fn() },
  useToastStore: { getState: () => ({ addToast: vi.fn() }) },
}))

import { api } from '../../lib/api'

const apiPostMock = api.post as ReturnType<typeof vi.fn>

function renderPage(withEmail = true) {
  return render(
    <MemoryRouter
      initialEntries={[
        withEmail
          ? { pathname: '/auth/password-expired', state: { email: 'expired@example.com' } }
          : '/auth/password-expired',
      ]}
    >
      <ForceChangePasswordPage />
    </MemoryRouter>,
  )
}

function fillAndSubmit({
  current = 'OldP@ssw0rd!',
  next = 'NewP@ssw0rd!',
  confirm = 'NewP@ssw0rd!',
} = {}) {
  fireEvent.change(screen.getByTestId('force-change-current'), {
    target: { value: current },
  })
  fireEvent.change(screen.getByTestId('force-change-new'), { target: { value: next } })
  fireEvent.change(screen.getByTestId('force-change-confirm'), {
    target: { value: confirm },
  })
  fireEvent.click(screen.getByTestId('force-change-submit'))
}

describe('ForceChangePasswordPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders the form with the expired account email', () => {
    renderPage()
    expect(screen.getByTestId('force-change-form')).toBeInTheDocument()
    // AuthLayout repeats the description in both columns (desktop + mobile).
    expect(screen.getAllByText(/expired@example\.com/).length).toBeGreaterThan(0)
  })

  it('posts email, current and new password to the change endpoint', async () => {
    apiPostMock.mockResolvedValueOnce({ message: 'ok' })
    renderPage()
    fillAndSubmit()
    await waitFor(() => {
      expect(apiPostMock).toHaveBeenCalledWith('/api/auth/expired-password/change', {
        email: 'expired@example.com',
        current_password: 'OldP@ssw0rd!',
        new_password: 'NewP@ssw0rd!',
      })
    })
  })

  it('shows the success panel after the API call succeeds', async () => {
    apiPostMock.mockResolvedValueOnce({ message: 'ok' })
    renderPage()
    fillAndSubmit()
    await waitFor(() => {
      expect(screen.getByTestId('force-change-success')).toBeInTheDocument()
    })
  })

  it('shows an inline alert when the API rejects the change', async () => {
    apiPostMock.mockRejectedValueOnce(new Error('Invalid credentials'))
    renderPage()
    fillAndSubmit()
    await waitFor(() => {
      const alert = screen.getByRole('alert')
      expect(alert).toHaveTextContent('Invalid credentials')
    })
    expect(screen.queryByTestId('force-change-success')).not.toBeInTheDocument()
  })

  it('blocks submit with validation errors when passwords do not match', async () => {
    apiPostMock.mockResolvedValueOnce({ message: 'ok' })
    renderPage()
    fillAndSubmit({ confirm: 'Different1!' })
    await waitFor(() => {
      expect(screen.getByText('Passwords do not match')).toBeInTheDocument()
    })
    expect(apiPostMock).not.toHaveBeenCalled()
  })

  it('shows field-level strength errors before calling the API', async () => {
    renderPage()
    fillAndSubmit({ next: 'alllowercase1!', confirm: 'alllowercase1!' })
    await waitFor(() => {
      expect(
        screen.getByText('Must contain at least one uppercase letter'),
      ).toBeInTheDocument()
    })
    expect(apiPostMock).not.toHaveBeenCalled()
  })
})
