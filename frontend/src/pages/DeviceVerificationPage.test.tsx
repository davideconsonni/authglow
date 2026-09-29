// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { DeviceVerificationPage } from './DeviceVerificationPage'
import { ROUTES } from '../lib/constants'

const mockApi = vi.hoisted(() => ({
  post: vi.fn().mockResolvedValue({}),
}))

const mockAuth = vi.hoisted(() => ({ isAuthenticated: true, isLoading: false }))

vi.mock('../lib/api', () => ({ api: mockApi }))

vi.mock('../hooks/useAuth', () => ({
  useAuth: () => ({ isAuthenticated: mockAuth.isAuthenticated, isLoading: mockAuth.isLoading }),
}))

vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))

function renderPage(query = '') {
  return render(
    <MemoryRouter initialEntries={[`/oauth2/device/verify${query}`]}>
      <DeviceVerificationPage />
    </MemoryRouter>,
  )
}

const DEVICE_INFO = {
  client_id: 'cli-1',
  scopes: ['read', 'write'],
  expires_at: '2030-01-01T00:00:00Z',
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
  mockAuth.isAuthenticated = true
  mockAuth.isLoading = false
})

describe('DeviceVerificationPage — gating', () => {
  it('shows a spinner while auth is loading', () => {
    mockAuth.isLoading = true
    const { container } = renderPage()
    expect(container.querySelector('.animate-spin')).not.toBeNull()
    expect(screen.queryByText('Device Verification')).not.toBeInTheDocument()
  })

  it('prompts anonymous visitors to sign in with a redirect', () => {
    mockAuth.isAuthenticated = false
    renderPage()
    expect(screen.getByText('Sign in to verify a device code.')).toBeInTheDocument()
    const href = screen.getByText('Sign In').closest('a')?.getAttribute('href')
    expect(href).toContain(ROUTES.AUTH.LOGIN)
    expect(href).toContain(`redirect=${encodeURIComponent(ROUTES.OAUTH_DEVICE_VERIFY)}`)
  })
})

describe('DeviceVerificationPage — code input', () => {
  it('disables Verify until a code is typed and rejects an empty lookup', () => {
    renderPage()
    const verify = screen.getByText('Verify Code').closest('button') as HTMLButtonElement
    expect(verify.disabled).toBe(true)

    const input = screen.getByPlaceholderText('ABCD-EFGH')
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(screen.getByRole('alert')).toHaveTextContent('Enter a code')

    fireEvent.change(input, { target: { value: 'abcd-efgh' } })
    expect(verify.disabled).toBe(false)
  })

  it('looks up a code and shows the review step', async () => {
    mockApi.post.mockResolvedValueOnce(DEVICE_INFO)
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('ABCD-EFGH'), {
      target: { value: 'abcd efgh' },
    })
    fireEvent.click(screen.getByText('Verify Code'))

    await waitFor(() => expect(screen.getByText('cli-1')).toBeInTheDocument())
    expect(screen.getByText('read')).toBeInTheDocument()
    expect(screen.getByText('write')).toBeInTheDocument()
    expect(screen.getByText('ABCDEFGH')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith('/api/oauth2/device/verify', {
      user_code: 'ABCDEFGH',
    })
  })

  it('shows an error when the code is invalid', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('nope'))
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('ABCD-EFGH'), {
      target: { value: 'bad-code' },
    })
    fireEvent.click(screen.getByText('Verify Code'))
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Invalid or expired code'),
    )
  })

  it('auto-looks-up a prefilled user_code from the query string', async () => {
    mockApi.post.mockResolvedValueOnce(DEVICE_INFO)
    renderPage('?user_code=abcd-efgh')
    await waitFor(() => expect(screen.getByText('cli-1')).toBeInTheDocument())
    expect(mockApi.post).toHaveBeenCalledWith('/api/oauth2/device/verify', {
      user_code: 'ABCD-EFGH',
    })
  })
})

describe('DeviceVerificationPage — approve / deny', () => {
  async function reachReview() {
    mockApi.post.mockResolvedValueOnce(DEVICE_INFO)
    renderPage()
    fireEvent.change(screen.getByPlaceholderText('ABCD-EFGH'), {
      target: { value: 'abcd-efgh' },
    })
    fireEvent.click(screen.getByText('Verify Code'))
    await screen.findByText('cli-1')
  }

  it('approves and can verify another code', async () => {
    await reachReview()
    fireEvent.click(screen.getByText('Approve'))
    await waitFor(() => expect(screen.getByText('Device Authorized')).toBeInTheDocument())
    expect(screen.getByText('You can return to your device now.')).toBeInTheDocument()
    expect(mockApi.post).toHaveBeenCalledWith('/api/oauth2/device/approve', {
      user_code: 'ABCD-EFGH',
    })

    fireEvent.click(screen.getByText('Verify another code'))
    expect(screen.getByPlaceholderText('ABCD-EFGH')).toBeInTheDocument()
    expect((screen.getByPlaceholderText('ABCD-EFGH') as HTMLInputElement).value).toBe('')
  })

  it('denies the request', async () => {
    await reachReview()
    fireEvent.click(screen.getByText('Deny'))
    await waitFor(() => expect(screen.getByText('Access Denied')).toBeInTheDocument())
    expect(mockApi.post).toHaveBeenCalledWith('/api/oauth2/device/deny', {
      user_code: 'ABCD-EFGH',
    })
  })

  it('surfaces an approve failure', async () => {
    await reachReview()
    mockApi.post.mockRejectedValueOnce(new Error('boom'))
    fireEvent.click(screen.getByText('Approve'))
    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Failed to approve'),
    )
  })

  it('surfaces a deny failure', async () => {
    await reachReview()
    mockApi.post.mockRejectedValueOnce(new Error('boom'))
    fireEvent.click(screen.getByText('Deny'))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('Failed to deny'))
  })
})
