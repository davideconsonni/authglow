// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import { Section } from './Section'
import { StatusBadge } from './StatusBadge'
import { EmptyState } from './EmptyState'
import { ErrorState } from './ErrorState'
import { LoadingState } from './LoadingState'
import { TableSkeleton } from './TableSkeleton'
import { SealStamp } from './SealStamp'
import { CopyButton } from './CopyButton'
import { JwtRibbon } from './JwtRibbon'
import { ToastContainer } from './Toast'
import { ConfirmDialog } from './ConfirmDialog'
import { ScopePicker } from './ScopePicker'

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../../lib/api', () => ({ api: mockApi }))

const mockToast = vi.hoisted(() => ({
  toasts: [] as Array<{ id: string; message: string; type: 'success' | 'error' | 'info' }>,
  removeToast: vi.fn(),
}))
vi.mock('../../stores/toastStore', () => ({
  useToastStore: () => ({ toasts: mockToast.toasts, removeToast: mockToast.removeToast }),
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockToast.toasts = []
  mockApi.get.mockResolvedValue({ scopes: ['read', 'write'] })
  Object.defineProperty(navigator, 'clipboard', {
    value: { writeText: vi.fn() },
    configurable: true,
  })
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('Section', () => {
  it('renders title, description, actions and children', () => {
    render(
      <Section title="Identity" description="Details" actions={<button>Act</button>}>
        <p>Body</p>
      </Section>,
    )
    expect(screen.getByText('Identity')).toBeInTheDocument()
    expect(screen.getByText('Details')).toBeInTheDocument()
    expect(screen.getByText('Act')).toBeInTheDocument()
    expect(screen.getByText('Body')).toBeInTheDocument()
  })
})

describe('StatusBadge', () => {
  it('renders the labels for true, false and null', () => {
    const { rerender } = render(<StatusBadge status={true} />)
    expect(screen.getByText('Active')).toBeInTheDocument()
    rerender(<StatusBadge status={false} trueLabel="On" falseLabel="Off" />)
    expect(screen.getByText('Off')).toBeInTheDocument()
    rerender(<StatusBadge status={null} trueLabel="On" falseLabel="Unknown" />)
    expect(screen.getByText('Unknown')).toBeInTheDocument()
  })
})

describe('EmptyState', () => {
  it('renders title, description and action', () => {
    render(<EmptyState title="Nothing here" description="Add something" action={<button>New</button>} />)
    expect(screen.getByText('Nothing here')).toBeInTheDocument()
    expect(screen.getByText('Add something')).toBeInTheDocument()
    expect(screen.getByText('New')).toBeInTheDocument()
  })

  it('renders with only a title', () => {
    render(<EmptyState title="Bare" />)
    expect(screen.getByText('Bare')).toBeInTheDocument()
  })
})

describe('ErrorState', () => {
  it('renders the defaults and fires retry', () => {
    const onRetry = vi.fn()
    render(<ErrorState onRetry={onRetry} />)
    expect(screen.getByText('Something went wrong')).toBeInTheDocument()
    fireEvent.click(screen.getByText('Try again'))
    expect(onRetry).toHaveBeenCalled()
  })

  it('renders a custom title and message without a retry button', () => {
    render(<ErrorState title="Nope" message="Broken" />)
    expect(screen.getByText('Nope')).toBeInTheDocument()
    expect(screen.getByText('Broken')).toBeInTheDocument()
    expect(screen.queryByText('Try again')).not.toBeInTheDocument()
  })
})

describe('LoadingState', () => {
  it('renders the default and a custom message', () => {
    const { rerender } = render(<LoadingState />)
    expect(screen.getByText('Loading...')).toBeInTheDocument()
    rerender(<LoadingState message="Fetching" />)
    expect(screen.getByText('Fetching')).toBeInTheDocument()
  })
})

describe('TableSkeleton', () => {
  it('renders the requested number of rows and columns', () => {
    const { container } = render(<TableSkeleton rows={2} columns={3} />)
    expect(container.querySelectorAll('.animate-pulse')).toHaveLength(9)
  })
})

describe('SealStamp', () => {
  it('renders the verified seal', () => {
    render(<SealStamp className="extra" />)
    expect(screen.getByTestId('token-seal')).toHaveAttribute('aria-label', 'Verified')
  })
})

describe('CopyButton', () => {
  it('copies the text on click', () => {
    render(<CopyButton text="copy-me" label="Copy" />)
    fireEvent.click(screen.getByLabelText('Copy'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('copy-me')
  })
})

describe('JwtRibbon', () => {
  it('renders the three segments for a three-part token', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    const payload = btoa(JSON.stringify({ sub: 'user-1' }))
    render(<JwtRibbon token={`${header}.${payload}.signature`} />)
    expect(screen.getByTestId('jwt-ribbon')).toBeInTheDocument()
    expect(screen.getByTitle(/alg: HS256/)).toBeInTheDocument()
    expect(screen.getByTitle(/sub: user-1/)).toBeInTheDocument()
  })

  it('renders nothing for a malformed token', () => {
    render(<JwtRibbon token="only.two" />)
    expect(screen.queryByTestId('jwt-ribbon')).not.toBeInTheDocument()
  })
})

describe('ToastContainer', () => {
  it('renders nothing when there are no toasts', () => {
    render(<ToastContainer />)
    expect(screen.queryByTestId('toast')).not.toBeInTheDocument()
  })

  it('renders toasts and dismisses them', () => {
    mockToast.toasts = [
      { id: 't1', message: 'Saved', type: 'success' },
      { id: 't2', message: 'Failed', type: 'error' },
    ]
    render(<ToastContainer />)
    expect(screen.getByText('Saved')).toBeInTheDocument()
    expect(screen.getByText('Failed')).toBeInTheDocument()
    expect(screen.getAllByTestId('toast')).toHaveLength(2)
    fireEvent.click(screen.getAllByLabelText('Dismiss notification')[0])
    expect(mockToast.removeToast).toHaveBeenCalledWith('t1')
  })
})

describe('ConfirmDialog', () => {
  it('renders nothing when closed', () => {
    render(
      <ConfirmDialog open={false} title="T" message="M" onConfirm={vi.fn()} onCancel={vi.fn()} />,
    )
    expect(screen.queryByTestId('confirm-dialog')).not.toBeInTheDocument()
  })

  it('confirms and cancels', () => {
    const onConfirm = vi.fn()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog
        open
        title="Delete?"
        message="This cannot be undone"
        confirmLabel="Delete"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />,
    )
    expect(screen.getByText('Delete?')).toBeInTheDocument()
    fireEvent.click(screen.getByTestId('confirm-dialog-confirm'))
    expect(onConfirm).toHaveBeenCalled()
    fireEvent.click(screen.getByTestId('confirm-dialog-cancel'))
    expect(onCancel).toHaveBeenCalled()
  })

  it('cancels on Escape and on backdrop click', () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog open title="T" message="M" onConfirm={vi.fn()} onCancel={onCancel} />,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onCancel).toHaveBeenCalledTimes(1)
    fireEvent.click(screen.getByTestId('confirm-dialog-backdrop'))
    expect(onCancel).toHaveBeenCalledTimes(2)
  })
})

describe('ScopePicker', () => {
  it('loads the available scopes and toggles them', async () => {
    const onChange = vi.fn()
    render(<ScopePicker value="openid" onChange={onChange} />)
    const chip = await screen.findByText('read')
    fireEvent.click(chip)
    expect(onChange).toHaveBeenCalledWith('openid read')
  })

  it('removes a selected scope', () => {
    const onChange = vi.fn()
    render(<ScopePicker value="openid read" onChange={onChange} />)
    fireEvent.click(screen.getByLabelText('Remove openid'))
    expect(onChange).toHaveBeenCalledWith('read')
  })

  it('adds a custom scope on click and on Enter', () => {
    const onChange = vi.fn()
    render(<ScopePicker value="openid" onChange={onChange} testId="scopes" />)
    const input = screen.getByTestId('scopes-custom-input')
    fireEvent.change(input, { target: { value: 'admin' } })
    fireEvent.click(screen.getByText('Add'))
    expect(onChange).toHaveBeenCalledWith('openid admin')

    onChange.mockClear()
    fireEvent.change(input, { target: { value: 'audit' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(onChange).toHaveBeenCalledWith('openid audit')
  })

  it('does not add an empty or duplicate custom scope', () => {
    const onChange = vi.fn()
    render(<ScopePicker value="openid" onChange={onChange} testId="scopes" />)
    const input = screen.getByTestId('scopes-custom-input')
    fireEvent.change(input, { target: { value: '   ' } })
    fireEvent.click(screen.getByText('Add'))
    expect(onChange).not.toHaveBeenCalled()
    fireEvent.change(input, { target: { value: 'openid' } })
    fireEvent.click(screen.getByText('Add'))
    expect(onChange).not.toHaveBeenCalled()
  })

  it('ignores interactions when disabled', async () => {
    const onChange = vi.fn()
    render(<ScopePicker value="openid" onChange={onChange} disabled testId="scopes" />)
    fireEvent.click(await screen.findByText('read'))
    expect(onChange).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('Remove openid')).not.toBeInTheDocument()
    expect(screen.getByTestId('scopes-custom-input')).toBeDisabled()
  })
})
