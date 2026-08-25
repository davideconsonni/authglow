import { usePlaygroundStore, type PlaygroundFlow } from '../../stores/playgroundStore'
import { PageHeader } from '../../components/layout/PageHeader'
import { FlowSidebar } from '../../components/playground/FlowSidebar'
import { FLOWS } from '../../components/playground/flows'
import { useDocumentTitle } from '../../hooks/useDocumentTitle'
import { AuthorizationCodeFlow } from '../../components/playground/flows/AuthorizationCodeFlow'
import { ClientCredentialsFlow } from '../../components/playground/flows/ClientCredentialsFlow'
import { PkceFlow } from '../../components/playground/flows/PkceFlow'
import { RefreshTokenFlow } from '../../components/playground/flows/RefreshTokenFlow'
import { IntrospectionFlow } from '../../components/playground/flows/IntrospectionFlow'
import { RevocationFlow } from '../../components/playground/flows/RevocationFlow'
import { ApiKeyExchangeFlow } from '../../components/playground/flows/ApiKeyExchangeFlow'
import { OidcDiscoveryFlow } from '../../components/playground/flows/OidcDiscoveryFlow'
import { UserInfoFlow } from '../../components/playground/flows/UserInfoFlow'
import { DeviceCodeFlow } from '../../components/playground/flows/DeviceCodeFlow'
import { TokenPreviewFlow } from '../../components/playground/flows/TokenPreviewFlow'
import { GenericRequestFlow } from '../../components/playground/flows/GenericRequestFlow'
import { DcrFlow } from '../../components/playground/flows/DcrFlow'
import { RpInitiatedLogoutFlow } from '../../components/playground/flows/RpInitiatedLogoutFlow'

const FLOW_TITLES: Record<PlaygroundFlow, string> = {
  'authorization-code': 'Authorization Code Flow',
  'client-credentials': 'Client Credentials Flow',
  'pkce': 'PKCE Flow',
  'refresh-token': 'Refresh Token Flow',
  'introspection': 'Token Introspection',
  'revocation': 'Token Revocation',
  'api-key-exchange': 'API Key Exchange',
  'oidc-discovery': 'OIDC Discovery',
  'userinfo': 'UserInfo',
  'device-code': 'Device Code Flow',
  'token-preview': 'Token Claims Preview',
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
  'userinfo': 'OpenID Connect UserInfo — fetch user claims with access token.',
  'device-code': 'RFC 8628 — Device authorization for TVs, CLIs, and input-constrained devices.',
  'token-preview': 'Preview the namespaced custom claims (RBAC, tenant, etc.) a client will receive in its access token.',
  'generic': 'Free-form API request builder for any endpoint.',
}

export function AdminPlaygroundPage() {
  useDocumentTitle('API Playground')
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
      case 'userinfo': return <UserInfoFlow />
      case 'device-code': return <DeviceCodeFlow />
      case 'token-preview': return <TokenPreviewFlow />
      case 'generic': return <GenericRequestFlow />
case 'dcr': return <DcrFlow />
case 'rp-logout': return <RpInitiatedLogoutFlow />
    }
  }

  return (
    <div>
      <PageHeader title="API Playground" description="Step-by-step OAuth2 / OIDC flow debugger. Tokens are automatically shared between flows." />

      <div className="flex flex-col md:flex-row rounded-2xl border border-surface-2 overflow-hidden bg-surface-1">
        <div className="hidden md:block">
          <FlowSidebar currentFlow={currentFlow} onSelect={setCurrentFlow} />
        </div>

        <div className="md:hidden border-b border-surface-2 bg-surface-1">
          <div className="p-3">
            <label className="mb-1.5 block text-xs font-semibold tracking-wider text-text-muted uppercase">
              Select Flow
            </label>
            <select
              value={currentFlow}
              onChange={(e) => setCurrentFlow(e.target.value as PlaygroundFlow)}
              className="w-full rounded-xl border border-surface-2 bg-surface-2 px-3 py-2.5 text-sm text-text-primary"
            >
              {FLOWS.map((flow) => (
                <option key={flow.id} value={flow.id}>
                  {flow.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex-1 p-4 sm:p-6 min-w-0">
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
