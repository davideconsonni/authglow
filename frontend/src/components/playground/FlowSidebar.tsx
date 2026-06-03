import {
  ArrowLeftRight,
  Building2,
  Eye,
  Fingerprint,
  Key,
  BookOpen,
  RefreshCw,
  Trash2,
  User,
  Braces,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { PlaygroundFlow } from '@/stores/playgroundStore'

interface FlowDef {
  id: PlaygroundFlow
  label: string
  icon: LucideIcon
  description: string
}

export const FLOWS: FlowDef[] = [
  {
    id: 'authorization-code',
    label: 'Authorization Code',
    icon: ArrowLeftRight,
    description: 'Browser-based flow with redirect and code exchange',
  },
  {
    id: 'client-credentials',
    label: 'Client Credentials',
    icon: Building2,
    description: 'Machine-to-machine authentication',
  },
  {
    id: 'pkce',
    label: 'PKCE',
    icon: Fingerprint,
    description: 'SPA/mobile flow with code challenge',
  },
  {
    id: 'refresh-token',
    label: 'Refresh Token',
    icon: RefreshCw,
    description: 'Exchange a refresh token for new tokens',
  },
  {
    id: 'introspection',
    label: 'Introspection',
    icon: Eye,
    description: 'Decode and validate tokens',
  },
  {
    id: 'revocation',
    label: 'Revocation',
    icon: Trash2,
    description: 'Revoke access or refresh tokens',
  },
  {
    id: 'api-key-exchange',
    label: 'API Key Exchange',
    icon: Key,
    description: 'Exchange an API key for a JWT',
  },
  {
    id: 'oidc-discovery',
    label: 'OIDC Discovery',
    icon: BookOpen,
    description: 'Explore the OIDC provider metadata',
  },
  {
    id: 'userinfo',
    label: 'UserInfo',
    icon: User,
    description: 'Fetch OIDC user claims via access token',
  },
  {
    id: 'generic',
    label: 'Generic Request',
    icon: Braces,
    description: 'Free-form API request builder',
  },
]

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
