// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ConsentScreen } from './ConsentScreen'

const mockApi = vi.hoisted(() => ({ postForm: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const BASE_PROPS = {
  sessionToken: 'sess-1',
  clientName: 'PaperSpace',
  scopes: [{ name: 'openid', description: 'Verify identity' }],
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.postForm.mockResolvedValue({ redirect_url: 'https://done' })
  Object.defineProperty(window, 'location', { value: { href: '' }, writable: true, configurable: true })
})

describe('ConsentScreen — approve / deny', () => {
  it('approves and follows the redirect', async () => {
    render(<ConsentScreen {...BASE_PROPS} />)
    fireEvent.click(screen.getByText('Approve'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith('/oauth2/consent', {
        session_token: 'sess-1',
        approved: 'true',
        remember: 'false',
      }),
    )
    expect(window.location.href).toBe('https://done')
  })

  it('approves with the remember flag', async () => {
    render(<ConsentScreen {...BASE_PROPS} />)
    fireEvent.click(screen.getByRole('checkbox'))
    fireEvent.click(screen.getByText('Approve'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith(
        '/oauth2/consent',
        expect.objectContaining({ remember: 'true' }),
      ),
    )
  })

  it('shows an approve error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('approve failed'))
    render(<ConsentScreen {...BASE_PROPS} />)
    fireEvent.click(screen.getByText('Approve'))
    expect(await screen.findByRole('alert')).toHaveTextContent('approve failed')
  })

  it('denies and follows the redirect', async () => {
    render(<ConsentScreen {...BASE_PROPS} />)
    fireEvent.click(screen.getByText('Deny'))
    await waitFor(() =>
      expect(mockApi.postForm).toHaveBeenCalledWith('/oauth2/consent', {
        session_token: 'sess-1',
        approved: 'false',
        remember: 'false',
      }),
    )
    expect(window.location.href).toBe('https://done')
  })

  it('shows a deny error and falls back for non-Error rejections', async () => {
    mockApi.postForm.mockRejectedValueOnce('boom')
    render(<ConsentScreen {...BASE_PROPS} />)
    fireEvent.click(screen.getByText('Deny'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to deny consent.')
  })

  it('does nothing without a session token', () => {
    render(<ConsentScreen {...BASE_PROPS} sessionToken={null} />)
    fireEvent.click(screen.getByText('Approve'))
    fireEvent.click(screen.getByText('Deny'))
    expect(mockApi.postForm).not.toHaveBeenCalled()
  })
})

describe('ConsentScreen — presentation', () => {
  it('renders preview mode with disabled actions', () => {
    render(<ConsentScreen {...BASE_PROPS} preview />)
    expect(screen.getByText(/This is a preview/)).toBeInTheDocument()
    expect(screen.queryByText('Approve')).not.toBeInTheDocument()
    expect(screen.queryByText('Deny')).not.toBeInTheDocument()
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
  })

  it('renders the known and default scope icons', () => {
    render(
      <ConsentScreen
        {...BASE_PROPS}
        scopes={[
          { name: 'openid', description: 'a' },
          { name: 'profile', description: 'b' },
          { name: 'email', description: 'c' },
          { name: 'offline_access', description: 'd' },
          { name: 'custom', description: 'e' },
        ]}
      />,
    )
    for (const name of ['openid', 'profile', 'email', 'offline_access', 'custom']) {
      expect(screen.getByText(name)).toBeInTheDocument()
    }
  })

  it('shows the redirect destination origin', () => {
    render(<ConsentScreen {...BASE_PROPS} redirectUri="https://app.example/cb?x=1" />)
    expect(screen.getByText('https://app.example')).toBeInTheDocument()
  })

  it('falls back to the raw string for an invalid redirect URI', () => {
    render(<ConsentScreen {...BASE_PROPS} redirectUri="not a url" />)
    expect(screen.getByText('not a url')).toBeInTheDocument()
  })

  it('renders the client description, logo and links', () => {
    render(
      <ConsentScreen
        {...BASE_PROPS}
        clientDescription="A nice app"
        clientLogoUri="https://x/logo.png"
        clientHomepageUri="https://home"
        clientTermsUri="https://terms"
        clientPrivacyUri="https://privacy"
      />,
    )
    expect(screen.getByText('A nice app')).toBeInTheDocument()
    const img = screen.getByAltText('PaperSpace logo')
    expect(img).toBeInTheDocument()
    fireEvent.error(img)
    expect((img as HTMLImageElement).style.display).toBe('none')
    expect(screen.getByText('Homepage')).toHaveAttribute('href', 'https://home')
    expect(screen.getByText('Terms of Service')).toHaveAttribute('href', 'https://terms')
    expect(screen.getByText('Privacy Policy')).toHaveAttribute('href', 'https://privacy')
  })

  it('renders the shield fallback without a logo', () => {
    render(<ConsentScreen {...BASE_PROPS} />)
    expect(screen.queryByAltText('PaperSpace logo')).not.toBeInTheDocument()
  })
})
