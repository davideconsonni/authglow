interface StatusBadgeProps {
  status: boolean | null
  trueLabel?: string
  falseLabel?: string
  trueClass?: string
  falseClass?: string
}

export function StatusBadge({
  status,
  trueLabel = 'Active',
  falseLabel = 'Inactive',
  trueClass = 'bg-semantic-success/10 text-semantic-success',
  falseClass = 'bg-semantic-error/10 text-semantic-error',
}: StatusBadgeProps) {
  const isTrue = status === true
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-lg px-2.5 py-1 text-xs font-medium ${isTrue ? trueClass : falseClass}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${isTrue ? 'bg-current' : 'bg-current opacity-50'}`} />
      {isTrue ? trueLabel : falseLabel}
    </span>
  )
}
