import { useAuthStore } from '@/stores/authStore'

export function useAuth() {
  const store = useAuthStore()

  return {
    user: store.user,
    token: store.token,
    isAuthenticated: store.isAuthenticated,
    isLoading: store.isLoading,
    login: store.login,
    logout: store.logout,
    setToken: store.setToken,
    setUser: store.setUser,
    fetchCurrentUser: store.fetchCurrentUser,
  }
}
