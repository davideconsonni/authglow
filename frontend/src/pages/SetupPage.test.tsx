// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { SetupPage } from './SetupPage'

const mockApi = vi.hoisted(() => ({ get: vi.fn() }))
vi.mock('../lib/api', () => ({ api: mockApi }))
vi.mock('../hooks/useDocumentTitle', () => ({ useDocumentTitle: vi.fn() }))
vi.mock('../components/shared/ThemeSwitcher', () => ({
  ThemeSwitcher: () => <div data-testid="theme-switcher" />,
}))
vi.mock('../components/setup/SetupWizard', () => ({
  SetupWizard: () => <div data-testid="setup-wizard" />,
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockApi.get.mockResolvedValue({ needs_setup: true })
})

describe('SetupPage', () => {
  it('shows the loading spinner while checking', () => {
    mockApi.get.mockReturnValue(new Promise(() => {}))
    render(<SetupPage />)
    expect(document.querySelector('.animate-spin')).not.toBeNull()
    expect(screen.queryByTestId('setup-wizard')).not.toBeInTheDocument()
  })

  it('shows the wizard when setup is needed', async () => {
    render(<SetupPage />)
    expect(await screen.findByTestId('setup-wizard')).toBeInTheDocument()
    expect(screen.getByText('Welcome to AuthGlow')).toBeInTheDocument()
  })

  it('shows the completed screen when setup is done', async () => {
    mockApi.get.mockResolvedValue({ needs_setup: false })
    render(<SetupPage />)
    expect(await screen.findByText('Setup already completed')).toBeInTheDocument()
    expect(screen.getByText('Sign in')).toHaveAttribute('href', '/auth/login')
    expect(screen.queryByTestId('setup-wizard')).not.toBeInTheDocument()
  })

  it('falls back to the wizard when the check fails', async () => {
    mockApi.get.mockRejectedValue(new Error('down'))
    render(<SetupPage />)
    expect(await screen.findByTestId('setup-wizard')).toBeInTheDocument()
  })
})
