import { AlertCircle, AlertTriangle, CheckCircle2, Info, Sparkles, X, type LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../../lib/utils'

export type BannerVariant = 'error' | 'success' | 'warning' | 'info' | 'demo'
export type BannerSize = 'sm' | 'md'

interface BannerProps {
  variant: BannerVariant
  children: ReactNode
  /** Visual size: 'md' = standard page banner (text-sm, py-3), 'sm' = compact (text-xs, py-2). Default 'md'. */
  size?: BannerSize
  /** When true, banner sticks to the top of its scrollable parent (use inside modals/drawers). */
  sticky?: boolean
  /** Show a dismiss button. Calls ``onDismiss`` when clicked. */
  onDismiss?: () => void
  /** Override the leading icon. Pass ``null`` to hide the icon. */
  icon?: LucideIcon | null
  /** ARIA role override. Defaults to 'alert' for error, 'status' otherwise (WAI-ARIA APG). */
  role?: 'alert' | 'status'
  className?: string
  'data-testid'?: string
}

const ICONS: Record<BannerVariant, LucideIcon> = {
  error: AlertCircle,
  success: CheckCircle2,
  warning: AlertTriangle,
  info: Info,
  demo: Sparkles,
}

const STYLES: Record<BannerVariant, string> = {
  error: 'border-semantic-error/30 bg-semantic-error/10 text-semantic-error',
  success: 'border-semantic-success/30 bg-semantic-success/10 text-semantic-success',
  warning: 'border-semantic-warning/30 bg-semantic-warning/10 text-semantic-warning',
  info: 'border-semantic-info/30 bg-semantic-info/10 text-semantic-info',
  demo: 'border-brand-violet/30 bg-brand-violet/10 text-brand-violet',
}

const SIZE_STYLES: Record<BannerSize, string> = {
  md: 'px-4 py-3 text-sm gap-3 [&_svg]:size-[18px]',
  sm: 'px-3 py-2 text-xs gap-2 [&_svg]:size-[14px]',
}

/**
 * Unified user-facing message banner.
 *
 * Replaces ~16 distinct inline error/success/info/warning styles that were
 * scattered across the app. Use this for:
 *  - Form submission errors (sticky inside modals)
 *  - Page-level critical context (e.g. "MFA not configured")
 *  - Inline save/toggle feedback when toasts are not appropriate
 *
 * For transient action-completion feedback (save succeeded, copy to clipboard),
 * prefer ``notify.success()`` from the toast store.
 */
export function Banner({
  variant,
  children,
  size = 'md',
  sticky = false,
  onDismiss,
  icon,
  role,
  className,
  'data-testid': testId = 'banner',
}: BannerProps) {
  const Icon = icon === null ? null : (icon ?? ICONS[variant])
  const ariaRole = role ?? (variant === 'error' ? 'alert' : 'status')

  return (
    <div
      role={ariaRole}
      data-testid={testId}
      data-variant={variant}
      className={cn(
        'flex items-start rounded-xl border',
        STYLES[variant],
        SIZE_STYLES[size],
        sticky && 'sticky top-0 z-10 backdrop-blur-sm',
        className,
      )}
    >
      {Icon && <Icon className="mt-0.5 shrink-0" aria-hidden="true" />}
      <div className="flex-1 leading-relaxed">{children}</div>
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss message"
          className="-m-1 shrink-0 rounded-md p-1 opacity-70 transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-current/30"
        >
          <X className="size-[14px]" aria-hidden="true" />
        </button>
      )}
    </div>
  )
}
