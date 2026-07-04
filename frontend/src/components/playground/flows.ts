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
  Smartphone,
  Sparkles,
  type LucideIcon,
} from 'lucide-react'
import type { PlaygroundFlow } from '@/stores/playgroundStore'

export interface FlowDef {
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
    id: 'device-code',
    label: 'Device Code',
    icon: Smartphone,
    description: 'RFC 8628 — TV/CLI device authorization flow',
  },
  {
    id: 'token-preview',
    label: 'Token Preview',
    icon: Sparkles,
    description: 'Preview the namespaced custom claims a client will receive',
  },
  {
    id: 'generic',
    label: 'Generic Request',
    icon: Braces,
    description: 'Free-form API request builder',
  },
]
