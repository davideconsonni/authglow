import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { api } from '@/lib/api'

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
}

interface AuthState {
  user: AuthUser | null
  isAuthenticated: boolean
  isLoading: boolean
}

interface AuthActions {
  setAuthenticated: (value: boolean) => void
  setUser: (user: AuthUser) => void
  login: (email: string, password: string) => Promise<AuthUser | { mfa_required: boolean }>
  logout: () => Promise<void>
  fetchCurrentUser: () => Promise<void>
}

type AuthStore = AuthState & AuthActions

export const useAuthStore = create<AuthStore>()(
  persist(
    (set, get) => ({
      user: null,
      isAuthenticated: false,
      isLoading: false,

      setAuthenticated: (value: boolean) => {
        set({ isAuthenticated: value })
        if (!value) {
          set({ user: null })
        }
      },

      setUser: (user: AuthUser) => {
        set({ user })
      },

      login: async (email: string, password: string) => {
        set({ isLoading: true })
        try {
          const response = await api.postForm<{
            access_token: string
            refresh_token?: string
            token_type: string
            mfa_required?: boolean
            session_token?: string
          }>('/api/token', {
            username: email,
            password,
          })

          if (response.mfa_required) {
            set({ isLoading: false })
            return { mfa_required: true, session_token: response.session_token } as unknown as { mfa_required: boolean; session_token: string }
          }

          set({
            isAuthenticated: true,
            isLoading: false,
          })

          await get().fetchCurrentUser()
          return {} as AuthUser
        } catch (err) {
          set({ isLoading: false })
          const message = err instanceof Error ? err.message : 'Login failed'
          throw new Error(message)
        }
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
          set({ user })
        } catch {
          // User info might not be available yet
        }
      },
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({ user: state.user, isAuthenticated: state.isAuthenticated }),
    },
  ),
)
