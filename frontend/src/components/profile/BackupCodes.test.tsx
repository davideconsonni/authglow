// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { BackupCodes } from './BackupCodes'

const mockApi = vi.hoisted(() => ({ post: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const CODES = ['AAAA-1111', 'BBBB-2222', 'CCCC-3333']

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.post.mockResolvedValue({})
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
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('BackupCodes', () => {
  it('renders the codes and the remaining count', () => {
    render(<BackupCodes codes={CODES} onRegenerate={vi.fn()} />)
    expect(screen.getByText('3 of 10 codes remaining')).toBeInTheDocument()
    expect(screen.getByText('AAAA-1111')).toBeInTheDocument()
    expect(screen.queryByText(/running low/)).not.toBeInTheDocument()
  })

  it('warns when two or fewer codes remain', () => {
    render(<BackupCodes codes={['AAAA-1111', 'BBBB-2222']} onRegenerate={vi.fn()} />)
    expect(screen.getByText('You are running low on backup codes. Regenerate soon.')).toBeInTheDocument()
  })

  it('copies all codes and resets the copied flag', () => {
    vi.useFakeTimers()
    render(<BackupCodes codes={CODES} onRegenerate={vi.fn()} />)
    fireEvent.click(screen.getByText('Copy all'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(CODES.join('\n'))
    expect(screen.getByText('Copied')).toBeInTheDocument()
    act(() => {
      vi.advanceTimersByTime(2000)
    })
    expect(screen.getByText('Copy all')).toBeInTheDocument()
  })

  it('downloads the codes as a text file', () => {
    vi.useFakeTimers()
    render(<BackupCodes codes={CODES} onRegenerate={vi.fn()} />)
    fireEvent.click(screen.getByText('Download'))
    expect(URL.createObjectURL).toHaveBeenCalled()
    expect(HTMLAnchorElement.prototype.click).toHaveBeenCalled()
    expect(URL.revokeObjectURL).toHaveBeenCalledWith('blob:codes')
    act(() => {
      vi.advanceTimersByTime(500)
    })
  })

  it('regenerates through the API and notifies the parent', async () => {
    const onRegenerate = vi.fn()
    render(<BackupCodes codes={CODES} onRegenerate={onRegenerate} />)
    fireEvent.click(screen.getByText('Regenerate'))
    await waitFor(() =>
      expect(mockApi.post).toHaveBeenCalledWith('/api/mfa/regenerate-backup-codes'),
    )
    expect(onRegenerate).toHaveBeenCalled()
  })

  it('swallows a regenerate failure without notifying the parent', async () => {
    const onRegenerate = vi.fn()
    mockApi.post.mockRejectedValueOnce(new Error('down'))
    render(<BackupCodes codes={CODES} onRegenerate={onRegenerate} />)
    fireEvent.click(screen.getByText('Regenerate'))
    await waitFor(() => expect(mockApi.post).toHaveBeenCalled())
    expect(onRegenerate).not.toHaveBeenCalled()
    expect(screen.getByText('Regenerate')).toBeInTheDocument()
  })
})
