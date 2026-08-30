import { CheckCircle, XCircle, Info, X } from 'lucide-react'
import { useToastStore, type ToastType } from '../../stores/toastStore'
import { cn } from '../../lib/utils'

const ICONS: Record<ToastType, typeof CheckCircle> = {
  success: CheckCircle,
  error: XCircle,
  info: Info,
}

const STYLES: Record<ToastType, string> = {
  success: 'border-semantic-success/40 bg-surface-1/95 text-semantic-success backdrop-blur-md shadow-glow-accent',
  error: 'border-semantic-error/40 bg-surface-1/95 text-semantic-error backdrop-blur-md shadow-glow-accent',
  info: 'border-semantic-info/40 bg-surface-1/95 text-semantic-info backdrop-blur-md shadow-glow-accent',
}

export function ToastContainer() {
  const { toasts, removeToast } = useToastStore()

  if (toasts.length === 0) return null

  return (
    <div
      className="fixed top-4 right-4 z-[100] flex flex-col gap-2 max-w-sm w-full pointer-events-none max-md:top-auto max-md:bottom-4 max-md:left-4 max-md:right-4 max-md:max-w-none"
      aria-live="polite"
      aria-atomic="false"
    >
      {toasts.map((t) => {
        const Icon = ICONS[t.type]
        return (
          <div
            key={t.id}
            role={t.type === 'error' ? 'alert' : 'status'}
            data-testid="toast"
            data-toast-type={t.type}
            className={cn(
              'pointer-events-auto flex items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-lg animate-in slide-in-from-right',
              STYLES[t.type],
            )}
          >
            <Icon size={18} className="shrink-0 mt-0.5" aria-hidden="true" />
            <span className="flex-1">{t.message}</span>
            <button
              onClick={() => removeToast(t.id)}
              className="shrink-0 rounded-md p-0.5 opacity-60 hover:opacity-100 transition-opacity"
              aria-label="Dismiss notification"
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )
      })}
    </div>
  )
}
