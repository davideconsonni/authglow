import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { api } from '../lib/api'

export interface AuthUser {
  id: string
  email: string
  first_name: string
  last_name: string
  avatar_url?: string
  is_active?: boolean
  created_at?: string
  email_verified?: boolean
  mfa_enabled: boolean
  roles: string[]
  scopes: string[]
  permissions: string[]
  is_federated: boolean
}

interface AuthState {
  user: AuthUser | null
  isAuthenticated: boolean
  isLoading: boolean
  _hydrated: boolean
}

interface AuthActions {
  setAuthenticated: (value: boolean) => void
  setUser: (user: AuthUser) => void
  logout: () => Promise<void>
  fetchCurrentUser: () => Promise<void>
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      _hydrated: false,

      setAuthenticated: (value: boolean) => {
        set({ isAuthenticated: value })
        if (!value) {
          set({ user: null })
          try {
            const event = String(Date.now())
            localStorage.setItem('auth-state-event', event)
            localStorage.removeItem('auth-state-event')
            if ('BroadcastChannel' in window) {
              const channel = new BroadcastChannel('authglow-auth')
              channel.postMessage('session-invalidated')
              channel.close()
            }
          } catch { /* storage unavailable */ }
        }
      },

      setUser: (user: AuthUser) => {
        set({ user })
      },

      logout: async () => {
        try {
          await api.post('/api/auth/logout')
        } catch {
          // Clear even if the server call fails
        }
        set({
          user: null,
          isAuthenticated: false,
        })
      },

      fetchCurrentUser: async () => {
        try {
          const user = await api.get<AuthUser>('/api/users/me')
          set({ user, isAuthenticated: true })
        } catch {
          set({ user: null, isAuthenticated: false })
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
      onRehydrateStorage: () => {
        return (state) => {
          if (state) {
            state._hydrated = true
          }
        }
      },
    },
  ),
)
