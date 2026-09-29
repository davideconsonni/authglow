// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ClientCredentialsFlow } from './ClientCredentialsFlow'

const mockStore = vi.hoisted(() => ({
  clientId: 'cc-client',
  clientSecret: 'cc-secret',
  scopes: 'read write',
  accessToken: '',
  refreshToken: '',
  apiKey: '',
  setClientId: vi.fn(),
  setClientSecret: vi.fn(),
  setScopes: vi.fn(),
  setAccessToken: vi.fn(),
  setRefreshToken: vi.fn(),
  setApiKey: vi.fn(),
  persistTokens: vi.fn(),
}))

vi.mock('../../../stores/playgroundStore', () => ({ usePlaygroundStore: () => mockStore }))

const mockApi = vi.hoisted(() => ({
  postForm: vi.fn(),
  post: vi.fn(),
  get: vi.fn(async () => ({ scopes: [] })),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
}))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.postForm.mockResolvedValue({ access_token: 'at-cc' })
})

describe('ClientCredentialsFlow', () => {
  it('requests a token with Basic auth and resets', async () => {
    render(<ClientCredentialsFlow />)
    expect(screen.getByText('Client ID *')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Next'))
    expect(screen.getByText('grant_type=client_credentials')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /Request Token/ }))
    await screen.findByText(/Access token obtained/)
    expect(mockApi.postForm).toHaveBeenCalledWith(
      '/oauth2/token',
      { grant_type: 'client_credentials', scope: 'read write' },
      { headers: { Authorization: `Basic ${btoa('cc-client:cc-secret')}` } },
    )
    expect(mockStore.setAccessToken).toHaveBeenCalledWith('at-cc')

    fireEvent.click(screen.getByText('Start Over'))
    expect(screen.getByText('Client ID *')).toBeInTheDocument()
  })

  it('surfaces a request error', async () => {
    mockApi.postForm.mockRejectedValueOnce(new Error('cc boom'))
    render(<ClientCredentialsFlow />)
    fireEvent.click(screen.getByText('Next'))
    fireEvent.click(screen.getByRole('button', { name: /Request Token/ }))
    await screen.findByText('cc boom')
  })
})
