// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'

const { mockAuth, mockApi } = vi.hoisted(() => ({
  mockAuth: { isAuthenticated: false },
  mockApi: { get: vi.fn(), patch: vi.fn().mockResolvedValue({}) },
}))

vi.mock('./useAuth', () => ({
  useAuth: () => ({ isAuthenticated: mockAuth.isAuthenticated }),
}))

vi.mock('../lib/api', () => ({
  api: mockApi,
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
    mockAuth.isAuthenticated = false
    mockApi.get.mockReset()
    mockApi.patch.mockReset()
    mockApi.patch.mockResolvedValue({})
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

describe('useTheme post-authentication sync', () => {
  const root = document.documentElement

  beforeEach(() => {
    mockMatchMedia(false)
    localStorage.clear()
    root.classList.remove('dark')
    root.removeAttribute('data-theme')
    mockAuth.isAuthenticated = false
    mockApi.get.mockReset()
    mockApi.patch.mockReset()
    mockApi.patch.mockResolvedValue({})
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it('preserves a dark theme picked before login after authentication', async () => {
    mockAuth.isAuthenticated = false
    const { result } = renderHook(() => useTheme())

    await act(async () => {
      await result.current.setTheme('dark')
    })
    expect(localStorage.getItem('auth-theme')).toBe('dark')
    expect(root.classList.contains('dark')).toBe(true)
    expect(mockApi.patch).not.toHaveBeenCalled() // pre-login: no server call

    mockAuth.isAuthenticated = true
    await act(async () => {
      result.current.setTheme('dark')
    })

    expect(localStorage.getItem('auth-theme')).toBe('dark')
    expect(root.classList.contains('dark')).toBe(true)
    expect(result.current.theme).toBe('dark')
  })

  it('does not pull from /api/profile/me/preferences on authentication', () => {
    mockAuth.isAuthenticated = false
    const { rerender } = renderHook(() => useTheme())

    mockAuth.isAuthenticated = true
    rerender()

    expect(mockApi.get).not.toHaveBeenCalled()
  })

  it('pushes the local default theme to the server when authenticated fresh', async () => {
    mockAuth.isAuthenticated = false
    const { rerender } = renderHook(() => useTheme())

    mockAuth.isAuthenticated = true
    await act(async () => {
      rerender()
    })

    expect(mockApi.patch).toHaveBeenCalledWith('/api/profile/me/preferences', {
      theme: 'professional',
    })
  })

  it('pushes the local dark theme to the server when authenticated with no recent override', async () => {
    // Simulate a returning session: localStorage already holds the user's
    // choice, no setTheme() was called in this mount, so manualOverrideRef
    // is false and the effect must propagate to the server.
    localStorage.setItem('auth-theme', 'dark')
    mockAuth.isAuthenticated = true

    renderHook(() => useTheme())

    expect(mockApi.patch).toHaveBeenCalledWith('/api/profile/me/preferences', {
      theme: 'dark',
    })
  })

  it('a theme change while authenticated still PATCHes the server', async () => {
    mockAuth.isAuthenticated = true
    const { result } = renderHook(() => useTheme())

    await act(async () => {
      await result.current.setTheme('dark')
    })

    expect(mockApi.patch).toHaveBeenCalledWith('/api/profile/me/preferences', {
      theme: 'dark',
    })
  })

  it('a failed PATCH does not break the local theme', async () => {
    mockAuth.isAuthenticated = true
    mockApi.patch.mockRejectedValueOnce(new Error('network'))
    const { result } = renderHook(() => useTheme())

    await act(async () => {
      await result.current.setTheme('dark')
    })

    expect(localStorage.getItem('auth-theme')).toBe('dark')
    expect(result.current.theme).toBe('dark')
    expect(root.classList.contains('dark')).toBe(true)
  })

  it('a failed PATCH on auth effect does not throw', async () => {
    mockApi.patch.mockRejectedValue(new Error('network'))
    mockAuth.isAuthenticated = false
    const { rerender } = renderHook(() => useTheme())

    mockAuth.isAuthenticated = true

    await expect(
      act(async () => {
        rerender()
      }),
    ).resolves.not.toThrow()
  })
})
