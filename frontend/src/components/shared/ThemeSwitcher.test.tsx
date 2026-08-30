// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'

vi.mock('../../hooks/useAuth', () => ({
  useAuth: () => ({ isAuthenticated: false }),
}))

vi.mock('../../lib/api', () => ({
  api: { get: vi.fn(), patch: vi.fn() },
}))

import { ThemeSwitcher } from './ThemeSwitcher'

function mockMatchMedia(dark = false) {
  const matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: query.includes('light') ? !dark : dark,
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatchEvent: vi.fn(),
  }))
  vi.stubGlobal('matchMedia', matchMedia)
}

describe('ThemeSwitcher', () => {
  const root = document.documentElement

  beforeEach(() => {
    mockMatchMedia(false)
    localStorage.clear()
    root.classList.remove('dark')
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('renders the two theme buttons with professional active by default', () => {
    render(<ThemeSwitcher />)
    expect(screen.getByTestId('theme-professional')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('theme-dark')).toHaveAttribute('aria-pressed', 'false')
  })

  it('switches to dark: toggles the html class and persists the choice', () => {
    render(<ThemeSwitcher />)
    fireEvent.click(screen.getByTestId('theme-dark'))

    expect(root.classList.contains('dark')).toBe(true)
    expect(localStorage.getItem('auth-theme')).toBe('dark')
    expect(screen.getByTestId('theme-dark')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('theme-professional')).toHaveAttribute('aria-pressed', 'false')
  })

  it('switches back to professional', () => {
    localStorage.setItem('auth-theme', 'dark')
    root.classList.add('dark')
    render(<ThemeSwitcher />)

    fireEvent.click(screen.getByTestId('theme-professional'))

    expect(root.classList.contains('dark')).toBe(false)
    expect(localStorage.getItem('auth-theme')).toBe('professional')
  })

  it('exposes an accessible group label', () => {
    render(<ThemeSwitcher size="sm" />)
    expect(screen.getByRole('group', { name: 'Color theme' })).toBeInTheDocument()
  })
})
