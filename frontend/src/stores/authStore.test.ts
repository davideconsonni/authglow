import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useAuthStore } from '../stores/authStore'

describe('authStore', () => {
  beforeEach(() => {
    const store = useAuthStore.getState()
    store.setAuthenticated(false)
    store.setUser(null as unknown as Parameters<typeof store.setUser>[0])
  })

  describe('no token stored in localStorage', () => {
    it('does not persist tokens', () => {
      const stored = localStorage.getItem('auth-storage')
      if (stored) {
        const parsed = JSON.parse(stored)
        expect(parsed.state).not.toHaveProperty('token')
        expect(parsed.state).not.toHaveProperty('refreshToken')
      }
    })

    it('persists user and isAuthenticated', () => {
      const store = useAuthStore.getState()
      store.setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })
      store.setAuthenticated(true)

      const stored = JSON.parse(localStorage.getItem('auth-storage') || '{}')
      expect(stored.state.user).toBeTruthy()
      expect(stored.state.isAuthenticated).toBe(true)
      expect(stored.state).not.toHaveProperty('token')
      expect(stored.state).not.toHaveProperty('refreshToken')
    })
  })

  describe('setAuthenticated', () => {
    it('sets isAuthenticated to true', () => {
      useAuthStore.getState().setAuthenticated(true)
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('clears user when setting isAuthenticated to false', () => {
      useAuthStore.getState().setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })
      useAuthStore.getState().setAuthenticated(false)
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('setUser', () => {
    it('sets the user object', () => {
      const user = {
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      }
      useAuthStore.getState().setUser(user)
      expect(useAuthStore.getState().user).toEqual(user)
    })
  })

  describe('logout', () => {
    it('clears isAuthenticated and user', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) })

      useAuthStore.getState().setAuthenticated(true)
      useAuthStore.getState().setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })

      await useAuthStore.getState().logout()
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })

    it('clears state synchronously even when the server call fails', async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error('network down'))

      useAuthStore.getState().setAuthenticated(true)
      useAuthStore.getState().setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })

      await useAuthStore.getState().logout()
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })
  })
})
