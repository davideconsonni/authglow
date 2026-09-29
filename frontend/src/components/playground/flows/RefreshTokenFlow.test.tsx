// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { RefreshTokenFlow } from './RefreshTokenFlow'

const mockStore = vi.hoisted(() => ({
  refreshToken: 'rt-existing',
  clientId: 'c-1',
  clientSecret: 's-1',
  accessToken: '',
  apiKey: '',
  setRefreshToken: vi.fn(),
  setClientId: vi.fn(),
  setClientSecret: vi.fn(),
  setAccessToken: vi.fn(),
  setApiKey: vi.fn(),
  persistTokens: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({ usePlaygroundStore: () => mockStore }))

const mockApi = vi.hoisted(() => ({
  postForm: vi.fn(),
  post: vi.fn(),
  get: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockStore.refreshToken = 'rt-existing'
  mockApi.postForm.mockResolvedValue({ access_token: 'at-2', refresh_token: 'rt-2' })
})

describe('RefreshTokenFlow', () => {
  it('shows the auto-fill hint and moves to the request step', () => {
    render(<RefreshTokenFlow />)
    expect(screen.getByText('Refresh token auto-filled from previous flow.')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Next'))
    expect(screen.getByText('grant_type=refresh_token')).toBeInTheDocument()
    expect(mockStore.setRefreshToken).toHaveBeenCalledWith('rt-existing')
  })

  it('refreshes tokens with Basic auth and resets', async () => {
    render(<RefreshTokenFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByText('Refresh Tokens'))
    await screen.findByText('New tokens obtained and auto-saved.')
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      { grant_type: 'refresh_token', refresh_token: 'rt-existing' },
      { headers: { Authorization: `Basic ${btoa('c-1:s-1')}` } },
    )
    expect(mockStore.persistTokens).toHaveBeenCalled()
    fireEvent.click(screen.getByText('Refresh Again'))
    expect(screen.getByText('Refresh token auto-filled from previous flow.')).toBeInTheDocument()
  })

  it('shows the empty hint when no token is stored', () => {
    mockStore.refreshToken = ''
    render(<RefreshTokenFlow />)
    expect(screen.getByText('Paste the refresh token to exchange for new tokens.')).toBeInTheDocument()
  })

  it('surfaces a refresh error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('refresh boom'))
    render(<RefreshTokenFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByText('Refresh Tokens'))
    await screen.findByText('refresh boom')
  })
})
