// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { RegisterForm } from './RegisterForm'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

function fillValid() {
  fireEvent.change(screen.getByPlaceholderText('John'), { target: { value: 'Ada' } })
  fireEvent.change(screen.getByPlaceholderText('Doe'), { target: { value: 'Lovelace' } })
  fireEvent.change(screen.getByPlaceholderText('you@example.com'), {
    target: { value: 'ada@example.com' },
  })
  fireEvent.change(screen.getByPlaceholderText('Create a strong password'), {
    target: { value: 'Abcdefgh123!' },
  })
  fireEvent.change(screen.getByPlaceholderText('Confirm your password'), {
    target: { value: 'Abcdefgh123!' },
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
})

describe('RegisterForm', () => {
  it('renders all fields', () => {
    render(<RegisterForm />)
    expect(screen.getByPlaceholderText('John')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('you@example.com')).toBeInTheDocument()
    expect(screen.getByText('Create account')).toBeInTheDocument()
  })

  it('shows validation errors on empty submit', async () => {
    render(<RegisterForm />)
    fireEvent.click(screen.getByText('Create account'))
    await screen.findByText('First name is required')
    expect(screen.getByText('Last name is required')).toBeInTheDocument()
    expect(screen.getByText('Invalid email address')).toBeInTheDocument()
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('rates password strength', () => {
    render(<RegisterForm />)
    const password = screen.getByPlaceholderText('Create a strong password')
    fireEvent.change(password, { target: { value: 'abc' } })
    expect(screen.getByText('Weak')).toBeInTheDocument()
    fireEvent.change(password, { target: { value: 'Abcdefgh123!' } })
    expect(screen.getByText('Strong')).toBeInTheDocument()
    expect(screen.getByText('At least 12 characters')).toBeInTheDocument()
  })

  it('toggles password visibility', () => {
    render(<RegisterForm />)
    const button = screen.getByLabelText('Show password')
    fireEvent.click(button)
    expect(screen.getByLabelText('Hide password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Create a strong password')).toHaveAttribute('type', 'text')
  })

  it('submits and redirects to login', async () => {
    render(<RegisterForm />)
    fillValid()
    fireEvent.click(screen.getByText('Create account'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/users', {
        first_name: 'Ada',
        last_name: 'Lovelace',
        email: 'ada@example.com',
        password: 'Abcdefgh123!',
      }),
    )
    expect(mockNavigate).toHaveBeenCalledWith(ROUTES.AUTH.LOGIN, {
      state: { registered: true, email: 'ada@example.com' },
    })
  })

  it('shows a general error on failure', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('email already registered'))
    render(<RegisterForm />)
    fillValid()
    fireEvent.click(screen.getByText('Create account'))
    await screen.findByText('email already registered')
  })
})
