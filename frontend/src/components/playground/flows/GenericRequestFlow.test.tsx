// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { GenericRequestFlow } from './GenericRequestFlow'

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
  mockApi.get.mockResolvedValue({ issuer: 'https://iss' })
  mockApi.post.mockResolvedValue({ ok: true })
  mockApi.put.mockResolvedValue({ ok: true })
  mockApi.patch.mockResolvedValue({ ok: true })
  mockApi.delete.mockResolvedValue({ ok: true })
})

describe('GenericRequestFlow', () => {
  it('sends a GET by default', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText(/issuer/)
    expect(mockApi.get).toHaveBeenCalledWith('/.well-known/openid-configuration')
  })

  it('sends POST with a parsed JSON body and shows the body editor', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('POST'))
    expect(screen.getByText('Request Body (JSON)')).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('{ "key": "value" }'), {
      target: { value: '{"a":1}' },
    })
    fireEvent.change(screen.getByPlaceholderText('/api/endpoint'), {
      target: { value: '/api/thing' },
    })
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText('200')
    expect(mockApi.post).toHaveBeenCalledWith('/api/thing', { a: 1 })
  })

  it('sends PUT', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('PUT'))
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText('200')
    expect(mockApi.put).toHaveBeenCalled()
  })

  it('sends PATCH', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('PATCH'))
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText('200')
    expect(mockApi.patch).toHaveBeenCalled()
  })

  it('sends DELETE', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('DELETE'))
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText('200')
    expect(mockApi.delete).toHaveBeenCalled()
  })

  it('reports invalid JSON bodies as errors', async () => {
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('POST'))
    fireEvent.change(screen.getByPlaceholderText('{ "key": "value" }'), {
      target: { value: '{ not json' },
    })
    fireEvent.click(screen.getByText('Send'))
    expect(mockApi.post).not.toHaveBeenCalled()
  })

  it('surfaces a request error', async () => {
    mockApi.get.mockRejectedValueOnce(new Error('net down'))
    render(<GenericRequestFlow />)
    fireEvent.click(screen.getByText('Send'))
    await screen.findByText('net down')
  })
})
