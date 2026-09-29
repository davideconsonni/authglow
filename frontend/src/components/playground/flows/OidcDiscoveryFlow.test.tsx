// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { OidcDiscoveryFlow } from './OidcDiscoveryFlow'

const mockApi = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  patch: vi.fn(),
  delete: vi.fn(),
  postForm: vi.fn(),
}))
vi.mock('../../../lib/api', () => ({ api: mockApi }))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.get.mockResolvedValue({ issuer: 'https://issuer.example' })
})

describe('OidcDiscoveryFlow', () => {
  it('fetches the discovery document and resets', async () => {
    render(<OidcDiscoveryFlow />)
    expect(screen.getByText('GET /.well-known/openid-configuration')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Fetch Discovery Document'))
    await screen.findByText(/issuer.example/)
    expect(mockApi.get).toHaveBeenCalledWith('/.well-known/openid-configuration')

    fireEvent.click(screen.getByText('Fetch Again'))
    expect(screen.getByText('GET /.well-known/openid-configuration')).toBeInTheDocument()
  })

  it('surfaces a fetch error', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('discovery down'))
    render(<OidcDiscoveryFlow />)
    fireEvent.click(screen.getByText('Fetch Discovery Document'))
    await screen.findByText('discovery down')
  })
})
