// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SetupWizard } from './SetupWizard'
import { ROUTES } from '../../lib/constants'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

function fillValid() {
  fireEvent.change(screen.getByPlaceholderText('admin@example.com'), {
    target: { value: 'admin@example.com' },
  })
  fireEvent.change(screen.getByPlaceholderText('Create a strong password'), {
    target: { value: 'Abcdefgh123!' },
  })
  fireEvent.change(screen.getByPlaceholderText('Paste the token from your server logs'), {
    target: { value: '  token-123  ' },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('SetupWizard', () => {
  it('renders all the fields', () => {
    render(<SetupWizard />)
    expect(screen.getByLabelText('Admin email')).toBeInTheDocument()
    expect(screen.getByLabelText('Admin password')).toBeInTheDocument()
    expect(screen.getByLabelText('Setup token')).toBeInTheDocument()
    expect(screen.getByText('Create admin account')).toBeInTheDocument()
  })

  it('validates empty fields', async () => {
    render(<SetupWizard />)
    fireEvent.click(screen.getByText('Create admin account'))
    await screen.findByText('Invalid email address')
    expect(screen.getByText('Must be at least 12 characters')).toBeInTheDocument()
    expect(screen.getByText('Setup token is required')).toBeInTheDocument()
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('enforces the password complexity rules', async () => {
    render(<SetupWizard />)
    fireEvent.change(screen.getByPlaceholderText('admin@example.com'), {
      target: { value: 'admin@example.com' },
    })
    fireEvent.change(screen.getByPlaceholderText('Create a strong password'), {
      target: { value: 'Abcdefghijk1' },
    })
    fireEvent.change(screen.getByPlaceholderText('Paste the token from your server logs'), {
      target: { value: 'token' },
    })
    fireEvent.click(screen.getByText('Create admin account'))
    await screen.findByText('Must contain a special character')
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('submits with the bearer token and shows the success screen', async () => {
    render(<SetupWizard />)
    fillValid()
    fireEvent.click(screen.getByText('Create admin account'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith(
        '/api/setup/create-admin',
        {
          email: 'admin@example.com',
          password: 'Abcdefgh123!',
          first_name: 'Admin',
          last_name: 'User',
        },
        { headers: { Authorization: 'Bearer token-123' } },
      ),
    )
    expect(await screen.findByText('Setup complete!')).toBeInTheDocument()
    expect(screen.getByText('Go to login')).toHaveAttribute('href', ROUTES.AUTH.LOGIN)
  })

  it('shows the API error message', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('invalid setup token'))
    render(<SetupWizard />)
    fillValid()
    fireEvent.click(screen.getByText('Create admin account'))
    await screen.findByText('invalid setup token')
    expect(screen.queryByText('Setup complete!')).not.toBeInTheDocument()
  })

  it('falls back to a generic message for non-Error rejections', async () => {
    mockApi.post.mockRejectedValueOnce('boom')
    render(<SetupWizard />)
    fillValid()
    fireEvent.click(screen.getByText('Create admin account'))
    await screen.findByText('Setup failed. Please try again.')
  })
})
