// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'

import { PageHeader } from './PageHeader'
import { TopBar } from './TopBar'
import { AppShell } from './AppShell'

const mockNavigate = vi.hoisted(() => vi.fn())
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
    Outlet: () => <div data-testid="outlet" />,
  }
})

const mockAuth = vi.hoisted(() => ({
  user: { first_name: 'Ada', last_name: 'Lovelace' } as Record<string, unknown> | null,
  logout: vi.fn(),
}))
vi.mock('../../hooks/useAuth', () => ({ useAuth: () => mockAuth }))

const mockDemo = vi.hoisted(() => ({
  meta: { demo_mode: false, demo_banner_text: undefined as string | undefined },
}))
vi.mock('../../hooks/useDemoMeta', () => ({ useDemoMeta: () => ({ meta: mockDemo.meta, loaded: true }) }))

vi.mock('../../components/layout/Sidebar', () => ({
  Sidebar: () => <div data-testid="sidebar" />,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockAuth.user = { first_name: 'Ada', last_name: 'Lovelace' }
  mockDemo.meta = { demo_mode: false, demo_banner_text: undefined }
})

describe('PageHeader', () => {
  it('renders the title, description and actions', () => {
    render(<PageHeader title="Profile" description="Manage it" actions={<button>Act</button>} />)
    expect(screen.getByTestId('page-title')).toHaveTextContent('Profile')
    expect(screen.getByText('Manage it')).toBeInTheDocument()
    expect(screen.getByText('Act')).toBeInTheDocument()
  })

  it('renders breadcrumbs with and without a link', () => {
    render(
      <PageHeader
        title="Profile"
        breadcrumbs={[{ label: 'Home', href: '/home' }, { label: 'Current' }]}
      />,
    )
    expect(screen.getByText('Home').tagName).toBe('A')
    expect(screen.getByText('Current').tagName).toBe('SPAN')
  })
})

describe('TopBar', () => {
  it('renders the user name and avatar initial', () => {
    render(<TopBar />)
    expect(screen.getByText('Ada Lovelace')).toBeInTheDocument()
    expect(screen.getByTestId('user-menu-trigger')).toBeInTheDocument()
  })

  it('falls back to the default label without a user', () => {
    mockAuth.user = null
    render(<TopBar />)
    expect(screen.getByText('User')).toBeInTheDocument()
  })
})

describe('AppShell', () => {
  it('renders the sidebar, top bar and outlet without a demo banner', () => {
    render(<AppShell />)
    expect(screen.getByTestId('sidebar')).toBeInTheDocument()
    expect(screen.getByTestId('user-menu-trigger')).toBeInTheDocument()
    expect(screen.getByTestId('outlet')).toBeInTheDocument()
    expect(screen.queryByText(/Demo environment/)).not.toBeInTheDocument()
  })

  it('shows the custom demo banner text in demo mode', () => {
    mockDemo.meta = { demo_mode: true, demo_banner_text: 'Custom demo notice' }
    render(<AppShell />)
    expect(screen.getByText('Custom demo notice')).toBeInTheDocument()
  })

  it('shows the default demo banner text when none is provided', () => {
    mockDemo.meta = { demo_mode: true, demo_banner_text: undefined }
    render(<AppShell />)
    expect(
      screen.getByText(
        'Demo environment — accounts and data are reset on every server restart.',
      ),
    ).toBeInTheDocument()
  })
})
