import { useEffect, useRef } from 'react'
import { AlertTriangle, Loader2 } from 'lucide-react'

interface ConfirmDialogProps {
  open: boolean
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: 'danger' | 'default'
  loading?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDialog({
  open,
  title,
  message,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  variant = 'default',
  loading = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const confirmRef = useRef<HTMLButtonElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)

  // Focus trap + Escape key
  useEffect(() => {
    if (!open) return

    previousFocusRef.current = document.activeElement as HTMLElement

    // Auto-focus confirm button
    requestAnimationFrame(() => {
      confirmRef.current?.focus()
    })

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !loading) {
        onCancel()
        return
      }

      // Focus trap
      if (e.key === 'Tab') {
        const dialog = document.querySelector('[data-testid="confirm-dialog"]') as HTMLElement | null
        if (!dialog) return

        const focusable = dialog.querySelectorAll<HTMLElement>(
          'button:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
        if (focusable.length === 0) return

        const first = focusable[0]
        const last = focusable[focusable.length - 1]

        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('keydown', handleKeyDown)
      // Restore focus
      previousFocusRef.current?.focus()
    }
  }, [open, loading, onCancel])

  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {!loading && (
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={onCancel} data-testid="confirm-dialog-backdrop" />
      )}
      <div className="relative z-10 mx-4 w-full sm:max-w-md sm:rounded-2xl rounded-xl border border-surface-2 bg-surface-1 p-6 shadow-glow-violet" data-testid="confirm-dialog" role="alertdialog" aria-modal="true" aria-labelledby="confirm-title" aria-describedby="confirm-message">
        <div className="flex items-start gap-4">
          <div
            className={`rounded-xl p-2 ${
              variant === 'danger' ? 'bg-semantic-error/10' : 'bg-surface-2'
            }`}
          >
            <AlertTriangle
              className={variant === 'danger' ? 'text-semantic-error' : 'text-semantic-warning'}
              size={24}
            />
          </div>
          <div className="flex-1">
            <h3 id="confirm-title" className="text-lg font-semibold text-text-primary">{title}</h3>
            <p id="confirm-message" className="mt-2 text-sm text-text-muted">{message}</p>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onCancel}
            disabled={loading}
            data-testid="confirm-dialog-cancel"
            className="rounded-xl bg-surface-2 px-4 min-h-[44px] py-2 text-sm font-medium text-text-secondary hover:bg-surface-3 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {cancelLabel}
          </button>
          <button
            ref={confirmRef}
            onClick={onConfirm}
            disabled={loading}
            data-testid="confirm-dialog-confirm"
            className={`rounded-xl px-4 min-h-[44px] py-2 text-sm font-medium text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed ${
              variant === 'danger'
                ? 'bg-semantic-error hover:bg-semantic-error/90'
                : 'bg-gradient-cta'
            }`}
          >
            {loading ? <Loader2 size={14} className="animate-spin" /> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
