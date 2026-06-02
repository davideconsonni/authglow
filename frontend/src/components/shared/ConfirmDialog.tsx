import { AlertTriangle } from 'lucide-react'

interface ConfirmDialogProps {
  open: boolean
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  variant?: 'danger' | 'default'
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
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  if (!open) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={onCancel} data-testid="confirm-dialog-backdrop" />
      <div className="relative z-10 w-full max-w-md rounded-2xl border border-surface-2 bg-surface-1 p-6 shadow-glow-violet" data-testid="confirm-dialog">
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
            <h3 className="text-lg font-semibold text-text-primary">{title}</h3>
            <p className="mt-2 text-sm text-text-muted">{message}</p>
          </div>
        </div>
        <div className="mt-6 flex justify-end gap-3">
          <button
            onClick={onCancel}
            data-testid="confirm-dialog-cancel"
            className="rounded-xl bg-surface-2 px-4 py-2 text-sm font-medium text-text-secondary hover:bg-surface-3 transition-colors"
          >
            {cancelLabel}
          </button>
          <button
            onClick={onConfirm}
            data-testid="confirm-dialog-confirm"
            className={`rounded-xl px-4 py-2 text-sm font-medium text-white transition-colors ${
              variant === 'danger'
                ? 'bg-semantic-error hover:bg-semantic-error/90'
                : 'bg-gradient-cta'
            }`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}
