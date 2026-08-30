import type { ReactNode } from 'react'
import { Key, ShieldCheck, Fingerprint, Globe, Cloud } from 'lucide-react'
import { ThemeSwitcher } from '../shared/ThemeSwitcher'

interface AuthLayoutProps {
  children: ReactNode
  title: string
  description?: string
}

const FEATURES = [
  { icon: Key, label: 'OAuth 2.0 / OIDC Server', desc: 'Full authorization server with PKCE, JWKS rotation, and DPoP' },
  { icon: ShieldCheck, label: 'Multi-Factor Authentication', desc: 'TOTP, backup codes, and trusted devices' },
  { icon: Fingerprint, label: 'Passkeys / WebAuthn', desc: 'Passwordless auth with biometrics and security keys' },
  { icon: Globe, label: 'Identity Federation', desc: 'CIE, SPID, Google, Microsoft, Apple — one login' },
  { icon: Cloud, label: 'Serverless & Simple', desc: 'No database required, deploy anywhere in 30 seconds' },
] as const

export function AuthLayout({ children, title, description }: AuthLayoutProps) {
  return (
    <div className="relative flex min-h-screen">
      <div className="absolute right-4 top-4 z-20">
        <ThemeSwitcher size="sm" />
      </div>
      {/* Brand column — desktop only */}
      <div className="auth-hero hidden w-1/2 flex-col justify-between bg-surface-1 p-12 lg:p-16 relative overflow-hidden md:flex">
        {/* Subtle background pattern */}
        <div className="absolute inset-0 opacity-[0.03]"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, currentColor 1px, transparent 0)`,
            backgroundSize: '32px 32px',
          }}
        />

        <div className="relative z-10">
          <h1 className="text-2xl font-bold gradient-text">AuthGlow</h1>
        </div>

        <div className="relative z-10 space-y-10">
          <div className="space-y-4">
            <h2 className="text-3xl lg:text-4xl font-bold text-text-primary leading-tight">{title}</h2>
            {description && (
              <p className="max-w-md text-text-muted leading-relaxed">{description}</p>
            )}
          </div>

          {/* Feature highlights */}
          <div className="space-y-4">
            {FEATURES.map((f, i) => (
              <div
                key={f.label}
                className="flex items-start gap-4 animate-fade-in"
                style={{ animationDelay: `${i * 120}ms`, animationFillMode: 'both' }}
              >
                <div className="icon-chip flex h-10 w-10 shrink-0 items-center justify-center rounded-xl">
                  <f.icon size={20} />
                </div>
                <div>
                  <p className="text-sm font-semibold text-text-primary">{f.label}</p>
                  <p className="text-xs text-text-muted mt-0.5">{f.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Form column */}
      <div className="flex w-full flex-col items-center justify-center bg-bg-primary p-8 md:w-1/2">
        <div className="mb-8 md:hidden">
          <h1 className="text-2xl font-bold gradient-text">AuthGlow</h1>
        </div>

        <div className="w-full max-w-md space-y-6">
          <div className="md:hidden">
            <h2 className="text-2xl font-bold text-text-primary">{title}</h2>
            {description && (
              <p className="mt-2 text-sm text-text-muted">{description}</p>
            )}
          </div>
          {children}
        </div>
      </div>
    </div>
  )
}
