import { cn } from '../../lib/utils'

interface SealStampProps {
  className?: string
}

export function SealStamp({ className }: SealStampProps) {
  return (
    <span className={cn('seal', className)} data-testid="token-seal" role="img" aria-label="Verified">
      <svg
        viewBox="0 0 24 24"
        className="h-1/2 w-1/2"
        fill="none"
        stroke="currentColor"
        strokeWidth={2.75}
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path className="seal-check" d="M5 12.5l4.5 4.5L19 7.5" />
      </svg>
    </span>
  )
}
