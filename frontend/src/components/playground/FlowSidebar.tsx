import { cn } from '@/lib/utils'
import type { PlaygroundFlow } from '@/stores/playgroundStore'
import { FLOWS } from './flows'

interface FlowSidebarProps {
  currentFlow: PlaygroundFlow
  onSelect: (flow: PlaygroundFlow) => void
}

export function FlowSidebar({ currentFlow, onSelect }: FlowSidebarProps) {
  return (
    <div className="w-56 shrink-0 border-r border-surface-2 bg-surface-1 rounded-l-2xl overflow-y-auto">
      <div className="px-4 py-4 border-b border-surface-2">
        <p className="text-xs font-semibold tracking-wider text-text-muted uppercase">
          OAuth2 Flows
        </p>
      </div>
      <div className="p-2 space-y-0.5">
        {FLOWS.map((flow) => (
          <button
            key={flow.id}
            data-testid={`flow-${flow.id}`}
            onClick={() => onSelect(flow.id)}
            className={cn(
              'flex w-full items-start gap-3 rounded-xl px-3 py-2.5 text-left transition-colors',
              currentFlow === flow.id
                ? 'bg-brand-violet/15 text-brand-violet'
                : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
            )}
          >
            <flow.icon size={18} className="shrink-0 mt-0.5" />
            <div className="min-w-0">
              <p className="text-sm font-medium truncate">{flow.label}</p>
              <p className="text-[11px] text-text-muted truncate">{flow.description}</p>
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}
