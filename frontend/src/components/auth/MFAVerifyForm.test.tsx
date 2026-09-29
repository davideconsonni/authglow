// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MFAVerifyForm } from './MFAVerifyForm'
import { ROUTES } from '../../lib/constants'

const mockNavigate = vi.hoisted(() => vi.fn())
const mockSearch = vi.hoisted(() => ({ params: 'session_token=sess-1' }))

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useSearchParams: () => [new URLSearchParams(mockSearch.params)],
    useNavigate: () => mockNavigate,
  }
})

const mockApi = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn(), postForm: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockAuthState = vi.hoisted(() => ({
  setAuthenticated: vi.fn(),
  fetchCurrentUser: vi.fn(),
}))
vi.mock('../../stores/authStore', () => ({
  useAuthStore: (selector?: (s: typeof mockAuthState) => unknown) =>
    selector ? selector(mockAuthState) : mockAuthState,
}))

function digits(container: HTMLElement) {
  return Array.from(container.querySelectorAll<HTMLInputElement>('input[type="text"]'))
}

beforeEach(() => {
  vi.clearAllMocks()
  mockSearch.params = 'session_token=sess-1'
  mockApi.post.mockResolvedValue({ access_token: 'at-1' })
})

describe('MFAVerifyForm', () => {
  it('renders six digit inputs and toggles to backup mode', () => {
    const { container } = render(<MFAVerifyForm />)
    expect(digits(container)).toHaveLength(6)
    fireEvent.click(screen.getByText('Use a backup code instead'))
    expect(screen.getByPlaceholderText('Enter 8+ character backup code')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Use authenticator app instead'))
    expect(digits(container)).toHaveLength(6)
  })

  it('ignores non-digit input', () => {
    const { container } = render(<MFAVerifyForm />)
    const input = digits(container)[0]
    fireEvent.change(input, { target: { value: 'a' } })
    expect(input.value).toBe('')
  })

  it('verifies a full code and navigates to the dashboard', async () => {
    const { container } = render(<MFAVerifyForm />)
    const inputs = digits(container)
    '123456'.split('').forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    expect(mockApi.post).toHaveBeenCalledWith('/api/mfa/verify-login', {
      session_token: 'sess-1',
      code: '123456',
    })
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith(ROUTES.DASHBOARD))
    expect(mockAuthState.setAuthenticated).toHaveBeenCalledWith(true)
  })

  it('uses the OAuth endpoint when oauth=1', async () => {
    mockSearch.params = 'session_token=sess-1&oauth=1'
    const { container } = render(<MFAVerifyForm />)
    const inputs = digits(container)
    '123456'.split('').forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalledWith('/api/mfa/verify-oauth-login', expect.anything()))
  })

  it('redirects when the response carries a redirect_url', async () => {
    Object.defineProperty(window, 'location', { value: { href: '' }, writable: true, configurable: true })
    mockApi.post.mockResolvedValueOnce({ redirect_url: 'https://client.example/cb' })
    const { container } = render(<MFAVerifyForm />)
    const inputs = digits(container)
    '123456'.split('').forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }))
    await waitFor(() => expect(window.location.href).toBe('https://client.example/cb'))
  })

  it('continues to consent when a consent_session_token is returned', async () => {
    Object.defineProperty(window, 'location', { value: { href: '' }, writable: true, configurable: true })
    mockApi.post.mockResolvedValueOnce({ consent_session_token: 'consent-1' })
    const { container } = render(<MFAVerifyForm />)
    const inputs = digits(container)
    '123456'.split('').forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }))
    await waitFor(() =>
      expect(window.location.href).toBe(
        '/oauth2/authorize?mfa_session_token=consent-1',
      ),
    )
  })

  it('shows a generic error on a non-lockout failure', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('bad'))
    const { container } = render(<MFAVerifyForm />)
    const inputs = digits(container)
    '123456'.split('').forEach((d, i) => fireEvent.change(inputs[i], { target: { value: d } }))
    await screen.findByText('Invalid code. Please try again.')
  })

  it('locks out after three failed attempts', async () => {
    const err = new Error('locked') as Error & { status: number }
    err.status = 429
    mockApi.post.mockRejectedValue(err)
    render(<MFAVerifyForm />)
    fireEvent.click(screen.getByText('Use a backup code instead'))
    fireEvent.change(screen.getByPlaceholderText('Enter 8+ character backup code'), {
      target: { value: 'ABCD1234' },
    })
    const submit = screen.getByText('Verify backup code')
    fireEvent.click(submit)
    await screen.findByText(/2 attempts remaining/)
    fireEvent.click(submit)
    await screen.findByText(/1 attempt remaining/)
    fireEvent.click(submit)
    await screen.findByText(/Locked. Try again in/)
  })
})
