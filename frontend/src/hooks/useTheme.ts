import { useState, useEffect, useCallback, useRef } from 'react'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'

export type Theme = 'light' | 'dark' | 'auto'

const THEME_KEY = 'auth-theme'

let serverSyncDone = false
let serverSyncPromise: Promise<void> | null = null

function getSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined') return 'dark'
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
}

function resolveTheme(theme: Theme): 'light' | 'dark' {
  if (theme === 'auto') return getSystemTheme()
  return theme
}

function applyTheme(resolved: 'light' | 'dark') {
  const root = document.documentElement
  if (resolved === 'light') {
    root.classList.add('light')
  } else {
    root.classList.remove('light')
  }
}

function readLocalTheme(): Theme {
  try {
    const saved = localStorage.getItem(THEME_KEY)
    if (saved === 'light' || saved === 'dark' || saved === 'auto') return saved
  } catch {
    /* localStorage unavailable */
  }
  return 'auto'
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
      const prefs = await api.get<{ theme?: Theme }>('/api/profile/me/preferences')
      const serverTheme = prefs.theme ?? 'auto'
      const localTheme = readLocalTheme()

      if (localTheme !== 'auto' && serverTheme === localTheme) {
        return
      }

      applyTheme(resolveTheme(serverTheme as Theme))
      saveLocalTheme(serverTheme as Theme)
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
    const next: Theme = currentResolved === 'dark' ? 'light' : 'dark'
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
