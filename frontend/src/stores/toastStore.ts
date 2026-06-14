import { create } from 'zustand'

export type ToastType = 'success' | 'error' | 'info'

export interface Toast {
  id: string
  type: ToastType
  message: string
}

interface ToastState {
  toasts: Toast[]
}

interface ToastActions {
  addToast: (type: ToastType, message: string) => void
  removeToast: (id: string) => void
}

type ToastStore = ToastState & ToastActions

let _counter = 0

export const useToastStore = create<ToastStore>((set, get) => ({
  toasts: [],

  addToast: (type, message) => {
    const id = `toast-${++_counter}`
    set({ toasts: [...get().toasts, { id, type, message }] })
    setTimeout(() => {
      set({ toasts: get().toasts.filter((t) => t.id !== id) })
    }, 4000)
  },

  removeToast: (id) => {
    set({ toasts: get().toasts.filter((t) => t.id !== id) })
  },
}))

/**
 * Static-style helpers for showing transient feedback from outside React
 * (event handlers, async callbacks, etc.). No hook needed.
 *
 *   notify.success('Provider enabled.')
 *   notify.error('Failed to delete: invalid token')
 *   notify.info('Copied to clipboard')
 */
export const notify = {
  success: (message: string) => useToastStore.getState().addToast('success', message),
  error: (message: string) => useToastStore.getState().addToast('error', message),
  info: (message: string) => useToastStore.getState().addToast('info', message),
}
