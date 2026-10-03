// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TrustedDevices } from './TrustedDevices'

const mockApi = vi.hoisted(() => ({ delete: vi.fn() }))
const mockQuery = vi.hoisted(() => ({ data: undefined as unknown, refetch: vi.fn() }))

vi.mock('../../lib/api', () => ({ api: mockApi }))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({ data: mockQuery.data, refetch: mockQuery.refetch }),
}))

const DEVICE = {
  id: 'd1',
  name: 'Laptop',
  ip_address: '10.0.0.1',
  created_at: '2026-01-01T10:00:00Z',
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = []
  mockApi.delete.mockResolvedValue({})
})

describe('TrustedDevices', () => {
  it('shows the empty state', () => {
    render(<TrustedDevices />)
    expect(screen.getByText('No trusted devices')).toBeInTheDocument()
  })

  it('renders the devices', () => {
    mockQuery.data = [DEVICE]
    render(<TrustedDevices />)
    expect(screen.getByText('Laptop')).toBeInTheDocument()
    expect(screen.getByText('10.0.0.1')).toBeInTheDocument()
  })

  it('removes a device and refetches', async () => {
    mockQuery.data = [DEVICE]
    render(<TrustedDevices />)
    fireEvent.click(screen.getByLabelText('Remove device Laptop'))
    await waitFor(() =>
      expect(mockApi.delete).toHaveBeenCalledWith('/api/mfa/trusted-devices/d1'),
    )
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('shows the removal error', async () => {
    mockQuery.data = [DEVICE]
    mockApi.delete.mockRejectedValueOnce(new Error('remove failed'))
    render(<TrustedDevices />)
    fireEvent.click(screen.getByLabelText('Remove device Laptop'))
    expect(await screen.findByRole('alert')).toHaveTextContent('remove failed')
  })

  it('falls back to a generic message for non-Error rejections', async () => {
    mockQuery.data = [DEVICE]
    mockApi.delete.mockRejectedValueOnce('boom')
    render(<TrustedDevices />)
    fireEvent.click(screen.getByLabelText('Remove device Laptop'))
    expect(await screen.findByRole('alert')).toHaveTextContent('Failed to remove device.')
  })
})
