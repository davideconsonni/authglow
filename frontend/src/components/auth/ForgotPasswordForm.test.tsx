// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ForgotPasswordForm, BackToLoginLink } from './ForgotPasswordForm'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockDemo = vi.hoisted(() => ({ demo_mode: false }))
vi.mock('../../hooks/useDemoMeta', () => ({ useDemoMeta: () => ({ meta: mockDemo }) }))

vi.mock('../../components/shared/DemoInbox', () => ({
  DemoInbox: () => <div data-testid="demo-inbox" />,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockDemo.demo_mode = false
  mockApi.post.mockResolvedValue({})
})

describe('ForgotPasswordForm', () => {
  it('renders the email field', () => {
    render(<ForgotPasswordForm />)
    expect(screen.getByPlaceholderText('you@example.com')).toBeInTheDocument()
    expect(screen.getByText('Send reset link')).toBeInTheDocument()
  })

  it('validates the email', async () => {
    render(<ForgotPasswordForm />)
    fireEvent.click(screen.getByText('Send reset link'))
    await screen.findByText('Invalid email address')
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('shows the confirmation screen on success', async () => {
    render(<ForgotPasswordForm />)
    fireEvent.change(screen.getByPlaceholderText('you@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByText('Send reset link'))
    await screen.findByText('Check your email')
    expect(mockApi.post).toHaveBeenCalledWith('/api/password/reset/request', {
      email: 'user@example.com',
    })
    expect(screen.queryByTestId('demo-inbox')).not.toBeInTheDocument()
  })

  it('shows the demo inbox in demo mode', async () => {
    mockDemo.demo_mode = true
    render(<ForgotPasswordForm />)
    fireEvent.change(screen.getByPlaceholderText('you@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByText('Send reset link'))
    await screen.findByTestId('demo-inbox')
  })

  it('shows a general error on failure', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('request failed'))
    render(<ForgotPasswordForm />)
    fireEvent.change(screen.getByPlaceholderText('you@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByText('Send reset link'))
    await screen.findByText('request failed')
  })

  it('renders the back-to-login link', () => {
    render(<BackToLoginLink />)
    expect(screen.getByText('Back to login').closest('a')).toHaveAttribute('href', '/auth/login')
  })
})
