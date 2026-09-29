// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { Sidebar } from './Sidebar'

const mockAuth = vi.hoisted(() => ({ user: null as Record<string, unknown> | null }))

vi.mock('../../hooks/useAuth', () => ({ useAuth: () => ({ user: mockAuth.user }) }))

function renderAt(path = '/dashboard') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Sidebar />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.user = { is_admin: false, permissions: [] }
  vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
    cb(0)
    return 0
  })
  document.body.style.overflow = ''
})

describe('Sidebar — section gating', () => {
  it('shows only the Account section for a plain user', () => {
    renderAt()
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Device Auths').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Administration')).toHaveLength(0)
  })

  it('shows the full Administration section for an admin', () => {
    mockAuth.user = { is_admin: true, permissions: [] }
    renderAt()
    expect(screen.getAllByText('Administration').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Users').length).toBeGreaterThan(0)
    expect(screen.getAllByText('RBAC').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Rate Limits').length).toBeGreaterThan(0)
  })

  it('shows only the entries allowed by the area permission', () => {
    mockAuth.user = { is_admin: false, permissions: ['users.manage'] }
    renderAt()
    expect(screen.getAllByText('Administration').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Users').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('OAuth Clients')).toHaveLength(0)
    expect(screen.queryAllByText('RBAC')).toHaveLength(0)
  })

  it('admin.read reveals every area entry', () => {
    mockAuth.user = { is_admin: false, permissions: ['admin.read'] }
    renderAt()
    expect(screen.getAllByText('RBAC').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Settings').length).toBeGreaterThan(0)
  })

  it('hides the Administration section for unrelated permissions', () => {
    mockAuth.user = { is_admin: false, permissions: ['profile.read'] }
    renderAt()
    expect(screen.queryAllByText('Administration')).toHaveLength(0)
  })

  it('handles a missing user', () => {
    mockAuth.user = null
    renderAt()
    expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0)
    expect(screen.queryAllByText('Administration')).toHaveLength(0)
  })
})

describe('Sidebar — collapse', () => {
  it('toggles the collapsed rail and its aria-label', () => {
    renderAt()
    expect(screen.getAllByText('Dashboard')).toHaveLength(2)
    fireEvent.click(screen.getByLabelText('Collapse sidebar'))
    // Collapsed hides the text labels (desktop and mobile alike).
    expect(screen.queryAllByText('Dashboard')).toHaveLength(0)
    expect(screen.getAllByText('AG').length).toBeGreaterThan(0)
    expect(screen.getByLabelText('Expand sidebar')).toBeInTheDocument()
    fireEvent.click(screen.getByLabelText('Expand sidebar'))
    expect(screen.getAllByText('Dashboard')).toHaveLength(2)
  })
})

describe('Sidebar — mobile drawer', () => {
  it('opens, locks scroll, and closes via the backdrop', () => {
    renderAt()
    fireEvent.click(screen.getByLabelText('Open sidebar'))
    expect(document.body.style.overflow).toBe('hidden')
    fireEvent.click(screen.getByTestId('sidebar-mobile-backdrop'))
    expect(document.body.style.overflow).toBe('')
  })

  it('closes via the close button', () => {
    renderAt()
    fireEvent.click(screen.getByLabelText('Open sidebar'))
    fireEvent.click(screen.getByLabelText('Close sidebar'))
    expect(document.body.style.overflow).toBe('')
  })

  it('closes on Escape and traps focus on Tab', () => {
    renderAt()
    fireEvent.click(screen.getByLabelText('Open sidebar'))
    // Non-shift Tab moves focus within the trap.
    fireEvent.keyDown(document, { key: 'Tab' })
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(document.body.style.overflow).toBe('')
  })

  it('wraps focus from the last item back to the first on Tab', () => {
    renderAt()
    fireEvent.click(screen.getByLabelText('Open sidebar'))
    const focusables = document.querySelectorAll<HTMLElement>(
      '[role="dialog"] nav a[href], [role="dialog"] nav button:not([disabled])',
    )
    const first = focusables[0]
    const last = focusables[focusables.length - 1]
    last.focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(document.activeElement).toBe(first)
  })
})

describe('Sidebar — active trail', () => {
  it('computes a trail for the active route', () => {
    const { container } = renderAt('/dashboard')
    expect(container.querySelector('.sidebar-active-trail')).not.toBeNull()
  })

  it('clears the trail when no route matches', () => {
    const { container } = renderAt('/no-such-route')
    expect(container.querySelector('.sidebar-active-trail')).toBeNull()
  })
})
