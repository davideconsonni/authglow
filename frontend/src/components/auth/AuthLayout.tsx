import type { ReactNode } from 'react'

interface AuthLayoutProps {
  children: ReactNode
  title: string
  description?: string
}

export function AuthLayout({ children, title, description }: AuthLayoutProps) {
  return (
    <div className="flex min-h-screen">
      {/* Brand column */}
      <div className="hidden w-1/2 flex-col justify-between bg-surface-1 p-12 md:flex">
        <div>
          <h1 className="text-2xl font-bold gradient-text">AuthGlow</h1>
        </div>
        <div className="space-y-6">
          <h2 className="text-3xl font-bold text-text-primary">{title}</h2>
          {description && (
            <p className="max-w-md text-text-muted">{description}</p>
          )}
        </div>
        <div className="text-sm text-text-muted">
          Enterprise CIAM Platform
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
