// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ResetPasswordForm } from './ResetPasswordForm'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

function renderForm() {
  return render(
    <MemoryRouter>
      <ResetPasswordForm />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('ResetPasswordForm', () => {
  it('renders the form and the lost-code link', () => {
    renderForm()
    expect(screen.getByPlaceholderText('XXXX-XXXX-XXXX')).toBeInTheDocument()
    expect(screen.getByText('Request a new one')).toBeInTheDocument()
    expect(screen.getByText('Reset password')).toBeInTheDocument()
  })

  it('validates the reset code format', async () => {
    renderForm()
    fireEvent.change(screen.getByPlaceholderText('XXXX-XXXX-XXXX'), {
      target: { value: 'AAAABBBBCCCCDD' },
    })
    fireEvent.click(screen.getByText('Reset password'))
    await screen.findByText(/Use the format XXXX-XXXX-XXXX/)
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('validates mismatched passwords', async () => {
    renderForm()
    fireEvent.change(screen.getByPlaceholderText('XXXX-XXXX-XXXX'), {
      target: { value: 'ABCD-EFGH-IJKL' },
    })
    fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'Different123!' },
    })
    fireEvent.click(screen.getByText('Reset password'))
    await screen.findByText('Passwords do not match')
  })

  it('toggles the new-password visibility', () => {
    renderForm()
    fireEvent.click(screen.getByLabelText('Show password'))
    expect(screen.getByPlaceholderText('Enter new password')).toHaveAttribute('type', 'text')
  })

  it('shows the success screen after resetting', async () => {
    renderForm()
    fireEvent.change(screen.getByPlaceholderText('XXXX-XXXX-XXXX'), {
      target: { value: 'ABCD-EFGH-IJKL' },
    })
    fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.click(screen.getByText('Reset password'))
    await screen.findByText('Password reset successful')
    expect(mockApi.post).toHaveBeenCalledWith('/api/password/reset/confirm', {
      reset_code: 'ABCD-EFGH-IJKL',
      new_password: 'Abcdefgh123!',
    })
  })

  it('shows a general error on failure', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('invalid reset code'))
    renderForm()
    fireEvent.change(screen.getByPlaceholderText('XXXX-XXXX-XXXX'), {
      target: { value: 'ABCD-EFGH-IJKL' },
    })
    fireEvent.change(screen.getByPlaceholderText('Enter new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.change(screen.getByPlaceholderText('Confirm new password'), {
      target: { value: 'Abcdefgh123!' },
    })
    fireEvent.click(screen.getByText('Reset password'))
    await screen.findByText('invalid reset code')
  })
})
