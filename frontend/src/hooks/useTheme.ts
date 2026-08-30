import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '../lib/api'
import { useAuth } from '../hooks/useAuth'

export type Theme = 'professional' | 'dark' | 'auto'

type ResolvedTheme = 'professional' | 'dark'

const THEME_KEY = 'auth-theme'

let serverSyncDone = false
let serverSyncPromise: Promise<void> | null = null

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined') return 'dark'
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'professional' : 'dark'
}

function resolveTheme(theme: Theme): ResolvedTheme {
  if (theme === 'auto') return getSystemTheme()
  return theme
}

function applyTheme(resolved: ResolvedTheme) {
  const root = document.documentElement
  root.classList.toggle('dark', resolved === 'dark')
  root.removeAttribute('data-theme')
}

function normalizeTheme(value: string | null): Theme | null {
  // 'light' was the old default theme; it is now 'professional'.
  if (value === 'light' || value === 'professional') return 'professional'
  if (value === 'dark' || value === 'auto') return value
  return null
}

function readLocalTheme(): Theme {
  try {
    const saved = normalizeTheme(localStorage.getItem(THEME_KEY))
    if (saved) return saved
  } catch {
    /* localStorage unavailable */
  }
  return 'professional'
}

function saveLocalTheme(theme: Theme) {
  try {
    localStorage.setItem(THEME_KEY, theme)
  } catch {
    /* localStorage unavailable */
  }
}

async function syncFromServer(): Promise<void> {
  if (serverSyncDone) return
  if (serverSyncPromise) return serverSyncPromise

  serverSyncPromise = (async () => {
    try {
      const prefs = await api.get<{ theme?: string }>('/api/profile/me/preferences')
      const serverTheme = normalizeTheme(prefs.theme ?? 'professional') ?? 'professional'
      const localTheme = readLocalTheme()

      if (localTheme !== 'auto' && serverTheme === localTheme) {
        return
      }

      applyTheme(resolveTheme(serverTheme))
      saveLocalTheme(serverTheme)
    } catch {
      /* offline: keep local theme */
    } finally {
      serverSyncDone = true
      serverSyncPromise = null
    }
  })()

  return serverSyncPromise
}

export function useTheme() {
  const { isAuthenticated } = useAuth()
  const [theme, setThemeState] = useState<Theme>(() => readLocalTheme())
  const manualOverrideRef = useRef(false)
  const manualTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const setTheme = useCallback(async (newTheme: Theme) => {
    const resolved = resolveTheme(newTheme)
    applyTheme(resolved)
    saveLocalTheme(newTheme)
    setThemeState(newTheme)

    manualOverrideRef.current = true
    if (manualTimerRef.current) clearTimeout(manualTimerRef.current)
    manualTimerRef.current = setTimeout(() => {
      manualOverrideRef.current = false
    }, 2000)

    if (isAuthenticated) {
      try {
        await api.patch('/api/profile/me/preferences', { theme: newTheme })
      } catch {
        /* save to server failed, theme stays locally */
      }
    }
  }, [isAuthenticated])

  const toggleTheme = useCallback(async () => {
    const currentResolved = resolveTheme(theme)
    const next: Theme = currentResolved === 'dark' ? 'professional' : 'dark'
    await setTheme(next)
  }, [theme, setTheme])

  useEffect(() => {
    const resolved = resolveTheme(theme)
    applyTheme(resolved)
  }, [theme])

  useEffect(() => {
    if (!isAuthenticated) return

    syncFromServer().then(() => {
      if (manualOverrideRef.current) return

      const serverTheme = readLocalTheme()
      if (serverTheme !== theme) {
        setThemeState(serverTheme)
      }
    })
  }, [isAuthenticated])

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: light)')
    const handleChange = () => {
      if (theme === 'auto') {
        applyTheme(getSystemTheme())
      }
    }
    mediaQuery.addEventListener('change', handleChange)
    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [theme])

  return { theme, setTheme, toggleTheme }
}
