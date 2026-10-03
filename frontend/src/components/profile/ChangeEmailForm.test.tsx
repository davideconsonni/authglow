// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ChangeEmailForm } from './ChangeEmailForm'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockAuth = vi.hoisted(() => ({ user: { email: 'old@example.com' } }))
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => mockAuth }))

function fillValid() {
  fireEvent.change(screen.getByPlaceholderText('New email address'), {
    target: { value: 'new@example.com' },
  })
  fireEvent.change(screen.getByPlaceholderText('Confirm with password'), {
    target: { value: 'correct horse' },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('ChangeEmailForm', () => {
  it('renders the fields and seeds the username hint', () => {
    render(<ChangeEmailForm />)
    expect(screen.getByText('Change Email')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('New email address')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Confirm with password')).toBeInTheDocument()
    expect(document.querySelector('input[type="hidden"]')).toHaveValue('old@example.com')
  })

  it('validates the email and the required password', async () => {
    render(<ChangeEmailForm />)
    fireEvent.change(screen.getByPlaceholderText('New email address'), { target: { value: 'not-an-email' } })
    // Dispatch the submit event directly: the native email input blocks the
    // click-driven submit (HTML5 constraint validation) before zod runs.
    fireEvent.submit(screen.getByText('Change email').closest('form') as HTMLFormElement)
    await screen.findByText('Invalid email')
    expect(screen.getByText('Password is required')).toBeInTheDocument()
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('submits and shows the success message', async () => {
    render(<ChangeEmailForm />)
    fillValid()
    fireEvent.click(screen.getByText('Change email'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/profile/me/change-email', {
        new_email: 'new@example.com',
        password: 'correct horse',
      }),
    )
    expect(await screen.findByText('Verification email sent to new address')).toBeInTheDocument()
  })

  it('shows the API error message', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('email already in use'))
    render(<ChangeEmailForm />)
    fillValid()
    fireEvent.click(screen.getByText('Change email'))
    await screen.findByText('email already in use')
  })

  it('falls back to a generic message for non-Error rejections', async () => {
    mockApi.post.mockRejectedValueOnce('boom')
    render(<ChangeEmailForm />)
    fillValid()
    fireEvent.click(screen.getByText('Change email'))
    await screen.findByText('Email change failed')
  })
})
