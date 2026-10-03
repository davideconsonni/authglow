// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { MFAEnrollment } from './MFAEnrollment'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => mockNavigate }
})

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const ENROLL_DATA = {
  qr_code: 'data:image/png;base64,AAAA',
  secret: 'TEST-SECRET-NOT-REAL',
  backup_codes: ['AAAA-1111', 'BBBB-2222'],
}

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((r) => {
    resolve = r
  })
  return { promise, resolve }
}

async function reachVerifyView() {
  fireEvent.click(screen.getByText('Enable MFA'))
  await screen.findByAltText('MFA QR Code')
}

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockImplementation(async (endpoint: string) => {
    if (endpoint === '/api/mfa/enroll') return ENROLL_DATA
    return {}
  })
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn() },
    configurable: true,
  })
  Object.defineProperty(URL, 'createObjectURL', {
    value: vi.fn(() => 'blob:codes'),
    configurable: true,
  })
  Object.defineProperty(URL, 'revokeObjectURL', { value: vi.fn(), configurable: true })
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('MFAEnrollment', () => {
  it('starts on the enroll step', () => {
    render(<MFAEnrollment />)
    expect(screen.getByText('Set up two-factor authentication')).toBeInTheDocument()
    expect(screen.getByText('Enable MFA')).toBeInTheDocument()
  })

  it('jumps to the manage step when MFA is already enabled', () => {
    render(<MFAEnrollment isEnabled />)
    expect(screen.getByText('Two-factor authentication is active')).toBeInTheDocument()
    expect(screen.getByText('Regenerate Backup Codes')).toBeInTheDocument()
  })

  it('shows a spinner while enrollment is in flight', async () => {
    const pending = deferred<unknown>()
    mockApi.post.mockReturnValueOnce(pending.promise)
    render(<MFAEnrollment />)
    fireEvent.click(screen.getByText('Enable MFA'))
    expect(document.querySelector('.animate-spin')).not.toBeNull()
    await act(async () => {
      pending.resolve(ENROLL_DATA)
      await pending.promise
    })
    expect(await screen.findByAltText('MFA QR Code')).toBeInTheDocument()
  })

  it('moves to the verify step with QR, secret and backup codes', async () => {
    render(<MFAEnrollment />)
    await reachVerifyView()
    expect(screen.getByText('TEST-SECRET-NOT-REAL')).toBeInTheDocument()
    expect(screen.getByText('AAAA-1111')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('000000')).toBeInTheDocument()
  })

  it('reports an enrollment failure and stays on the enroll step', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('server down'))
    render(<MFAEnrollment />)
    fireEvent.click(screen.getByText('Enable MFA'))
    await screen.findByText('server down')
    expect(screen.getByText('Enable MFA')).toBeInTheDocument()
  })

  it('falls back to a generic enrollment error for non-Error rejections', async () => {
    mockApi.post.mockRejectedValueOnce('nope')
    render(<MFAEnrollment />)
    fireEvent.click(screen.getByText('Enable MFA'))
    await screen.findByText('Failed to start MFA enrollment.')
  })

  it('copies the shared secret', async () => {
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.click(screen.getByLabelText('Copy secret'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('TEST-SECRET-NOT-REAL')
  })

  it('copies all backup codes', async () => {
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.click(screen.getByText('Copy'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('AAAA-1111\nBBBB-2222')
    expect(screen.getByText('Copied')).toBeInTheDocument()
  })

  it('downloads the backup codes', async () => {
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.click(screen.getByText('Download'))
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:codes')
  })

  it('validates the verification code length', async () => {
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123' } })
    fireEvent.click(screen.getByText('Verify & Enable'))
    await screen.findByText('Enter the 6-digit code from your app')
    expect(mockApi.post).not.toHaveBeenCalledWith('/api/mfa/verify', expect.anything())
  })

  it('verifies, refreshes the user and navigates to security', async () => {
    const onRefreshUser = vi.fn().mockResolvedValue(undefined)
    render(<MFAEnrollment onRefreshUser={onRefreshUser} />)
    await reachVerifyView()
    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '123456' } })
    fireEvent.click(screen.getByText('Verify & Enable'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/mfa/verify', { code: '123456' }),
    )
    expect(onRefreshUser).toHaveBeenCalled()
    expect(mockNavigate).toHaveBeenCalledWith('/security')
  })

  it('reports a verification failure', async () => {
    mockApi.post.mockImplementation(async (endpoint: string) => {
      if (endpoint === '/api/mfa/enroll') return ENROLL_DATA
      throw new Error('bad code')
    })
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '000000' } })
    fireEvent.click(screen.getByText('Verify & Enable'))
    await screen.findByText('bad code')
    expect(mockNavigate).not.toHaveBeenCalled()
  })

  it('falls back to a generic verification error for non-Error rejections', async () => {
    mockApi.post.mockImplementation(async (endpoint: string) => {
      if (endpoint === '/api/mfa/enroll') return ENROLL_DATA
      throw 'nope'
    })
    render(<MFAEnrollment />)
    await reachVerifyView()
    fireEvent.change(screen.getByPlaceholderText('000000'), { target: { value: '000000' } })
    fireEvent.click(screen.getByText('Verify & Enable'))
    await screen.findByText('Verification failed. Please try again.')
  })

  it('regenerates backup codes from the manage step', async () => {
    render(<MFAEnrollment isEnabled />)
    fireEvent.click(screen.getByText('Regenerate Backup Codes'))
    expect(await screen.findByAltText('MFA QR Code')).toBeInTheDocument()
  })

  it('reports a regenerate failure and returns to the manage step', async () => {
    mockApi.post.mockRejectedValueOnce(new Error('regen failed'))
    render(<MFAEnrollment isEnabled />)
    fireEvent.click(screen.getByText('Regenerate Backup Codes'))
    await screen.findByText('regen failed')
    expect(screen.getByText('Two-factor authentication is active')).toBeInTheDocument()
  })
})
