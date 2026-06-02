import { usePlaygroundStore, type PlaygroundFlow } from '@/stores/playgroundStore'
import { PageHeader } from '@/components/layout/PageHeader'
import { FlowSidebar } from '@/components/playground/FlowSidebar'
import { AuthorizationCodeFlow } from '@/components/playground/flows/AuthorizationCodeFlow'
import { ClientCredentialsFlow } from '@/components/playground/flows/ClientCredentialsFlow'
import { PkceFlow } from '@/components/playground/flows/PkceFlow'
import { RefreshTokenFlow } from '@/components/playground/flows/RefreshTokenFlow'
import { IntrospectionFlow } from '@/components/playground/flows/IntrospectionFlow'
import { RevocationFlow } from '@/components/playground/flows/RevocationFlow'
import { ApiKeyExchangeFlow } from '@/components/playground/flows/ApiKeyExchangeFlow'
import { OidcDiscoveryFlow } from '@/components/playground/flows/OidcDiscoveryFlow'
import { GenericRequestFlow } from '@/components/playground/flows/GenericRequestFlow'

const FLOW_TITLES: Record<PlaygroundFlow, string> = {
  'authorization-code': 'Authorization Code Flow',
  'client-credentials': 'Client Credentials Flow',
  'pkce': 'PKCE Flow',
  'refresh-token': 'Refresh Token Flow',
  'introspection': 'Token Introspection',
  'revocation': 'Token Revocation',
  'api-key-exchange': 'API Key Exchange',
  'oidc-discovery': 'OIDC Discovery',
  'generic': 'Generic Request',
}

const FLOW_DESCRIPTIONS: Record<PlaygroundFlow, string> = {
  'authorization-code': 'Browser-based OAuth2 flow with redirect and authorization code exchange.',
  'client-credentials': 'Machine-to-machine authentication using client credentials grant.',
  'pkce': 'Proof Key for Code Exchange — secure authorization for SPAs and mobile apps.',
  'refresh-token': 'Exchange a refresh token for new access tokens.',
  'introspection': 'RFC 7662 — Introspect token metadata and validity.',
  'revocation': 'RFC 7009 — Revoke access or refresh tokens.',
  'api-key-exchange': 'Exchange an API key for a short-lived JWT access token.',
  'oidc-discovery': 'OpenID Connect Discovery — explore provider metadata.',
  'generic': 'Free-form API request builder for any endpoint.',
}

export function AdminPlaygroundPage() {
  const { currentFlow, setCurrentFlow } = usePlaygroundStore()

  const title = FLOW_TITLES[currentFlow]
  const desc = FLOW_DESCRIPTIONS[currentFlow]

  const renderFlow = () => {
    switch (currentFlow) {
      case 'authorization-code': return <AuthorizationCodeFlow />
      case 'client-credentials': return <ClientCredentialsFlow />
      case 'pkce': return <PkceFlow />
      case 'refresh-token': return <RefreshTokenFlow />
      case 'introspection': return <IntrospectionFlow />
      case 'revocation': return <RevocationFlow />
      case 'api-key-exchange': return <ApiKeyExchangeFlow />
      case 'oidc-discovery': return <OidcDiscoveryFlow />
      case 'generic': return <GenericRequestFlow />
    }
  }

  return (
    <div>
      <PageHeader title="API Playground" description="Step-by-step OAuth2 / OIDC flow debugger. Tokens are automatically shared between flows." />

      <div className="flex rounded-2xl border border-surface-2 overflow-hidden">
        <FlowSidebar currentFlow={currentFlow} onSelect={setCurrentFlow} />

        <div className="flex-1 p-6 min-w-0">
          <div className="mb-4">
            <h2 className="text-lg font-semibold text-text-primary">{title}</h2>
            <p className="text-xs text-text-muted mt-0.5">{desc}</p>
          </div>
          {renderFlow()}
        </div>
      </div>
    </div>
  )
}
