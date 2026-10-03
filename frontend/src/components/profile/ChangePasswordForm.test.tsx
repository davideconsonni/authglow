// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { ChangePasswordForm } from './ChangePasswordForm'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockAuth = vi.hoisted(() => ({ user: { email: 'user@example.com' } }))
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => mockAuth }))

function fillValid() {
  fireEvent.change(screen.getByPlaceholderText('Enter current password'), {
    target: { value: 'old-password' },
  })
  fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
    target: { value: 'Abcdefgh123!' },
  })
  fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
    target: { value: 'Abcdefgh123!' },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('ChangePasswordForm', () => {
  it('renders the fields and the username hint', () => {
    render(<ChangePasswordForm />)
    expect(screen.getByText('Change Password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter current password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter new password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Confirm new password')).toBeInTheDocument()
    expect(document.querySelector('input[type="hidden"]')).toHaveValue('user@example.com')
  })

  it('blocks submit when the fields are missing', async () => {
    render(<ChangePasswordForm />)
    fireEvent.click(screen.getByText('Update password'))
    await act(async () => {})
    expect(mockApi.post).not.toHaveBeenCalled()
    expect(screen.getByText('Update password')).toBeInTheDocument()
  })

  it('blocks submit when the new password fails the policy', async () => {
    render(<ChangePasswordForm />)
    fireEvent.change(screen.getByPlaceholderText('Enter current password'), { target: { value: 'old' } })
    fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
      target: { value: 'abcdefgh123!' },
    })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'abcdefgh123!' },
    })
    fireEvent.click(screen.getByText('Update password'))
    await act(async () => {})
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('rejects a password mismatch on the confirmation field', async () => {
    render(<ChangePasswordForm />)
    fireEvent.change(screen.getByPlaceholderText('Enter current password'), { target: { value: 'old' } })
    fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'Different123!' },
    })
    fireEvent.click(screen.getByText('Update password'))
    await screen.findByText('Passwords do not match')
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('toggles the visibility of both password fields', () => {
    render(<ChangePasswordForm />)
    const toggles = screen.getAllByLabelText('Toggle visibility')
    expect(toggles).toHaveLength(2)
    const current = screen.getByPlaceholderText('Enter current password')
    const next = screen.getByPlaceholderText('Enter new password')
    expect(current).toHaveAttribute('type', 'password')
    fireEvent.click(toggles[0])
    expect(current).toHaveAttribute('type', 'text')
    fireEvent.click(toggles[1])
    expect(next).toHaveAttribute('type', 'text')
  })

  it('submits, shows success and redirects to login', async () => {
    render(<ChangePasswordForm />)
    fillValid()
    fireEvent.click(screen.getByText('Update password'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/profile/me/change-password', {
        current_password: 'old-password',
        new_password: 'Abcdefgh123!',
      }),
    )
    expect(
      await screen.findByText(
        'Password changed. All sessions were revoked — redirecting you to sign in again...',
      ),
    ).toBeInTheDocument()
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.LOGIN, { replace: true }), {
      timeout: 3000,
    })
  })

  it('shows the API error message', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('wrong current password'))
    render(<ChangePasswordForm />)
    fillValid()
    fireEvent.click(screen.getByText('Update password'))
    await screen.findByText('wrong current password')
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it('falls back to a generic message for non-Error rejections', async () => {
    mockApi.post.mockRejectedValueOnce('nope')
    render(<ChangePasswordForm />)
    fillValid()
    fireEvent.click(screen.getByText('Update password'))
    await screen.findByText('Password change failed')
  })
})
