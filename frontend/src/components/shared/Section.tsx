import type { ReactNode } from 'react'

interface SectionProps {
  title: string
  description?: string
  children: ReactNode
  actions?: ReactNode
}

export function Section({ title, description, children, actions }: SectionProps) {
  return (
    <section className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">{title}</h2>
          {description && <p className="mt-1 text-xs text-text-muted">{description}</p>}
        </div>
        {actions}
      </div>
      {children}
    </section>
  )
}
