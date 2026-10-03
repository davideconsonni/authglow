// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { PasskeyManager } from './PasskeyManager'

const mockApi = vi.hoisted(() => ({
  post: vi.fn().mockResolvedValue({ challenge: 'c' }),
  delete: vi.fn().mockResolvedValue({}),
}))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockQuery = vi.hoisted(() => ({
  data: undefined as unknown,
  refetch: vi.fn(),
}))
vi.mock('../../hooks/useApi', () => ({
  useApiQuery: () => ({ data: mockQuery.data, refetch: mockQuery.refetch, isLoading: false }),
}))

const mockWebauthn = vi.hoisted(() => ({ startRegistration: vi.fn() }))
vi.mock('@simplewebauthn/browser', () => ({
  startRegistration: mockWebauthn.startRegistration,
}))

const REG_RESULT = {
  id: 'cred-1',
  response: { clientDataJSON: 'cd', attestationObject: 'ao', transports: ['usb', 'nfc'] },
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

beforeEach(() => {
  vi.clearAllMocks()
  mockQuery.data = []
  mockApi.post.mockResolvedValue({ challenge: 'c' })
  mockApi.delete.mockResolvedValue({})
  mockWebauthn.startRegistration.mockResolvedValue(REG_RESULT)
})

describe('PasskeyManager', () => {
  it('shows the empty state', () => {
    render(<PasskeyManager />)
    expect(screen.getByText('No passkeys registered yet')).toBeInTheDocument()
  })

  it('renders the passkeys with transports and last-used info', () => {
    mockQuery.data = [
      {
        credential_id: 'c1',
        name: 'MacBook',
        device_type: 'platform',
        transports: ['internal'],
        created_at: '2026-01-01T10:00:00Z',
        last_used_at: '2026-02-01T10:00:00Z',
      },
      {
        credential_id: 'c2',
        name: 'YubiKey',
        device_type: 'unknown-type',
        transports: [],
        created_at: '2026-01-02T10:00:00Z',
        last_used_at: null,
      },
    ]
    render(<PasskeyManager />)
    expect(screen.getByText('MacBook')).toBeInTheDocument()
    expect(screen.getByText('internal')).toBeInTheDocument()
    expect(screen.getByText(/Last used/)).toBeInTheDocument()
    expect(screen.getByText('YubiKey')).toBeInTheDocument()
    expect(screen.getByText('unknown-type')).toBeInTheDocument()
  })

  it('registers a new passkey and refetches the list', async () => {
    render(<PasskeyManager />)
    fireEvent.click(screen.getByText('Add Passkey'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/passkey/register/begin', {
        name: navigator.userAgent,
      }),
    )
    expect(mockApi.post).toHaveBeenCalledWith('/api/passkey/register/complete', {
      credential_id: 'cred-1',
      client_data_json: 'cd',
      attestation_object: 'ao',
      transports: ['usb', 'nfc'],
    })
    expect(await screen.findByText('Passkey added successfully')).toBeInTheDocument()
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('shows a spinner while registering', async () => {
    const pending = deferred<typeof REG_RESULT>()
    mockWebauthn.startRegistration.mockReturnValueOnce(pending.promise)
    render(<PasskeyManager />)
    fireEvent.click(screen.getByText('Add Passkey'))
    await waitFor(() => expect(document.querySelector('.animate-spin')).not.toBeNull())
    await act(async () => {
      pending.resolve(REG_RESULT)
      await pending.promise
    })
  })

  it('reports a registration error', async () => {
    mockWebauthn.startRegistration.mockRejectedValueOnce(new Error('user cancelled'))
    render(<PasskeyManager />)
    fireEvent.click(screen.getByText('Add Passkey'))
    await screen.findByText('user cancelled')
  })

  it('falls back to a generic registration error for non-Error rejections', async () => {
    mockWebauthn.startRegistration.mockRejectedValueOnce('nope')
    render(<PasskeyManager />)
    fireEvent.click(screen.getByText('Add Passkey'))
    await screen.findByText('Failed to register passkey')
  })

  it('removes a passkey after confirmation', async () => {
    mockQuery.data = [
      {
        credential_id: 'c1',
        name: 'MacBook',
        device_type: 'platform',
        transports: ['internal'],
        created_at: '2026-01-01T10:00:00Z',
        last_used_at: null,
      },
    ]
    render(<PasskeyManager />)
    fireEvent.click(screen.getByLabelText('Remove passkey MacBook'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await waitFor(() => expect(mockApi.delete).toHaveBeenCalledWith('/api/passkey/c1'))
    expect(mockQuery.refetch).toHaveBeenCalled()
  })

  it('cancels the removal without calling the API', () => {
    mockQuery.data = [
      {
        credential_id: 'c1',
        name: 'MacBook',
        device_type: 'platform',
        transports: ['internal'],
        created_at: '2026-01-01T10:00:00Z',
        last_used_at: null,
      },
    ]
    render(<PasskeyManager />)
    fireEvent.click(screen.getByLabelText('Remove passkey MacBook'))
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(mockApi.delete).not.toHaveBeenCalled()
  })

  it('reports a removal error', async () => {
    mockApi.delete.mockRejectedValueOnce(new Error('delete failed'))
    mockQuery.data = [
      {
        credential_id: 'c1',
        name: 'MacBook',
        device_type: 'platform',
        transports: ['internal'],
        created_at: '2026-01-01T10:00:00Z',
        last_used_at: null,
      },
    ]
    render(<PasskeyManager />)
    fireEvent.click(screen.getByLabelText('Remove passkey MacBook'))
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    await screen.findByText('delete failed')
  })
})
