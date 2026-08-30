// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'

vi.mock('./useAuth', () => ({
  useAuth: () => ({ isAuthenticated: false }),
}))

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), patch: vi.fn() },
}))

import { useTheme } from './useTheme'

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

describe('useTheme', () => {
  const root = document.documentElement

  beforeEach(() => {
    mockMatchMedia(false)
    localStorage.clear()
    root.classList.remove('dark')
    root.removeAttribute('data-theme')
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('defaults to professional with no dark class', () => {
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('professional')
    expect(root.classList.contains('dark')).toBe(false)
  })

  it('applies the professional theme (plain root, no attribute) and persists it', async () => {
    const { result } = renderHook(() => useTheme())

    await act(async () => {
      await result.current.setTheme('professional')
    })

    expect(result.current.theme).toBe('professional')
    expect(root.classList.contains('dark')).toBe(false)
    expect(root.getAttribute('data-theme')).toBeNull()
    expect(localStorage.getItem('auth-theme')).toBe('professional')
  })

  it('clears the dark class when switching back from dark to professional', async () => {
    localStorage.setItem('auth-theme', 'professional')
    const { result } = renderHook(() => useTheme())

    await act(async () => {
      await result.current.setTheme('dark')
    })

    expect(root.classList.contains('dark')).toBe(true)

    await act(async () => {
      await result.current.setTheme('professional')
    })

    expect(root.classList.contains('dark')).toBe(false)
    expect(localStorage.getItem('auth-theme')).toBe('professional')
  })

  it('migrates legacy "light" stored values to professional', () => {
    localStorage.setItem('auth-theme', 'light')
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('professional')
    expect(root.classList.contains('dark')).toBe(false)
  })

  it('strips a legacy data-theme attribute on mount', () => {
    root.setAttribute('data-theme', 'professional')
    localStorage.setItem('auth-theme', 'professional')
    renderHook(() => useTheme())
    expect(root.getAttribute('data-theme')).toBeNull()
  })

  it('falls back to professional for unknown stored values', () => {
    localStorage.setItem('auth-theme', 'bogus')
    const { result } = renderHook(() => useTheme())
    expect(result.current.theme).toBe('professional')
  })
})
