// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ApiKeyExchangeFlow } from './ApiKeyExchangeFlow'

const mockStore = vi.hoisted(() => ({
  apiKey: 'ak-existing',
  accessToken: '',
  refreshToken: '',
  clientId: '',
  clientSecret: '',
  setApiKey: vi.fn(),
  setAccessToken: vi.fn(),
  setRefreshToken: vi.fn(),
  setClientId: vi.fn(),
  setClientSecret: vi.fn(),
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
  mockStore.apiKey = 'ak-existing'
  mockApi.post.mockResolvedValue({ access_token: 'at-ak' })
})

describe('ApiKeyExchangeFlow', () => {
  it('exchanges an API key for tokens and resets', async () => {
    render(<ApiKeyExchangeFlow />)
    expect(screen.getByText('POST /api/token/api-key')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Exchange API Key'))
    await screen.findByText('Tokens obtained. Use them in other flows.')
    expect(mockStore.setApiKey).toHaveBeenCalledWith('ak-existing')
    expect(mockApi.post).toHaveBeenCalledWith('/api/token/api-key', undefined, {
      headers: { Authorization: 'Bearer ak-existing' },
    })
    expect(mockStore.persistTokens).toHaveBeenCalled()

    fireEvent.click(screen.getByText('Exchange Another Key'))
    expect(screen.getByText('API Key *')).toBeInTheDocument()
  })

  it('disables the exchange button without a key', () => {
    mockStore.apiKey = ''
    render(<ApiKeyExchangeFlow />)
    const button = screen.getByText('Exchange API Key').closest('button') as HTMLButtonElement
    expect(button.disabled).toBe(true)
  })

  it('surfaces an exchange error', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('ak boom'))
    render(<ApiKeyExchangeFlow />)
    fireEvent.click(screen.getByText('Exchange API Key'))
    await screen.findByText('ak boom')
  })
})
