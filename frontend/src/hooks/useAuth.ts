import { useAuthStore } from '../stores/authStore'

export function useAuth() {
  const store = useAuthStore()

  return {
    user: store.user,
    isAuthenticated: store.isAuthenticated,
    isLoading: store.isLoading,
    logout: store.logout,
    setAuthenticated: store.setAuthenticated,
    setUser: store.setUser,
    fetchCurrentUser: store.fetchCurrentUser,
  }
}
