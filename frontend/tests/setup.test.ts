import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')

function readPackageJson() {
  return JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf-8'))
}

describe('Fase 1.1 — Tailwind CSS v4 + PostCSS', () => {
  it('tailwindcss è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('tailwindcss')
  })

  it('@tailwindcss/postcss è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('@tailwindcss/postcss')
  })

  it('postcss è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('postcss')
  })

  it('postcss.config.js esiste', () => {
    const configPath = resolve(ROOT, 'postcss.config.js')
    expect(existsSync(configPath)).toBe(true)
  })

  it('postcss.config.js contiene la configurazione @tailwindcss/postcss', async () => {
    const config = await import(resolve(ROOT, 'postcss.config.js'))
    expect(config.default.plugins).toHaveProperty('@tailwindcss/postcss')
  })

  it('tailwindcss è importabile correttamente', async () => {
    const tw = await import('tailwindcss')
    expect(tw).toBeDefined()
  })
})

describe('Fase 1.2 — shadcn/ui installazione e componenti base', () => {
  const COMPONENTS = [
    'button',
    'input',
    'card',
    'dialog',
    'dropdown-menu',
    'tabs',
    'table',
    'popover',
    'tooltip',
    'command',
    'drawer',
  ]

  it('components.json esiste', () => {
    expect(existsSync(resolve(ROOT, 'components.json'))).toBe(true)
  })

  it.each(COMPONENTS)('il componente "%s" esiste in src/components/ui/', (name) => {
    const filePath = resolve(ROOT, 'src', 'components', 'ui', `${name}.tsx`)
    expect(existsSync(filePath)).toBe(true)
  })

  it('clsx è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('clsx')
  })

  it('tailwind-merge è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('tailwind-merge')
  })

  it('class-variance-authority è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('class-variance-authority')
  })

  it('lucide-react è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('lucide-react')
  })

  it('cn() helper esiste in lib/utils.ts', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'utils.ts'))
    expect(mod.cn).toBeDefined()
    expect(typeof mod.cn).toBe('function')
  })
})

describe('Fase 1.3 — Design token AuthGlow via @theme in globals.css', () => {
  let css: string

  beforeAll(() => {
    css = readFileSync(resolve(ROOT, 'src', 'styles', 'globals.css'), 'utf-8')
  })

  it('globals.css contiene @theme block', () => {
    expect(css).toContain('@theme')
  })

  it('@theme contiene --color-bg-primary', () => {
    expect(css).toMatch(/--color-bg-primary:\s*var\(--color-bg-primary\)/)
  })
  it('@theme contiene --color-bg-secondary', () => {
    expect(css).toMatch(/--color-bg-secondary:\s*var\(--color-bg-secondary\)/)
  })
  it('@theme contiene --color-bg-tertiary', () => {
    expect(css).toMatch(/--color-bg-tertiary:\s*var\(--color-bg-tertiary\)/)
  })

  it('@theme contiene --color-surface-1', () => {
    expect(css).toMatch(/--color-surface-1:\s*var\(--color-surface-1\)/)
  })
  it('@theme contiene --color-surface-2', () => {
    expect(css).toMatch(/--color-surface-2:\s*var\(--color-surface-2\)/)
  })
  it('@theme contiene --color-surface-3', () => {
    expect(css).toMatch(/--color-surface-3:\s*var\(--color-surface-3\)/)
  })

  it('@theme contiene --color-brand-violet', () => {
    expect(css).toMatch(/--color-brand-violet:\s*var\(--color-brand-violet\)/)
  })
  it('@theme contiene --color-brand-magenta', () => {
    expect(css).toMatch(/--color-brand-magenta:\s*var\(--color-brand-magenta\)/)
  })
  it('@theme contiene --color-brand-blue', () => {
    expect(css).toMatch(/--color-brand-blue:\s*var\(--color-brand-blue\)/)
  })

  it('@theme contiene --color-semantic-success', () => {
    expect(css).toMatch(/--color-semantic-success:\s*var\(--color-semantic-success\)/)
  })
  it('@theme contiene --color-semantic-warning', () => {
    expect(css).toMatch(/--color-semantic-warning:\s*var\(--color-semantic-warning\)/)
  })
  it('@theme contiene --color-semantic-error', () => {
    expect(css).toMatch(/--color-semantic-error:\s*var\(--color-semantic-error\)/)
  })
  it('@theme contiene --color-semantic-info', () => {
    expect(css).toMatch(/--color-semantic-info:\s*var\(--color-semantic-info\)/)
  })

  it('@theme contiene --color-text-primary', () => {
    expect(css).toMatch(/--color-text-primary:\s*var\(--color-text-primary\)/)
  })
  it('@theme contiene --color-text-secondary', () => {
    expect(css).toMatch(/--color-text-secondary:\s*var\(--color-text-secondary\)/)
  })
  it('@theme contiene --color-text-muted', () => {
    expect(css).toMatch(/--color-text-muted:\s*var\(--color-text-muted\)/)
  })

  it('@theme include font-family Inter', () => {
    expect(css).toContain('Inter')
  })

  it('@theme contiene glow-violet shadow', () => {
    expect(css).toMatch(/--shadow-glow-violet/)
  })
  it('@theme contiene glow-magenta shadow', () => {
    expect(css).toMatch(/--shadow-glow-magenta/)
  })
  it('@theme contiene glow-blue shadow', () => {
    expect(css).toMatch(/--shadow-glow-blue/)
  })

  it('@theme contiene gradient-cta', () => {
    expect(css).toMatch(/--background-image-gradient-cta/)
  })
  it('@theme contiene gradient-secondary', () => {
    expect(css).toMatch(/--background-image-gradient-secondary/)
  })

  it('@theme contiene radius-card', () => {
    expect(css).toContain('--radius-card:')
  })

  it('@theme contiene animate-accordion-down', () => {
    expect(css).toContain('--animate-accordion-down:')
  })
  it('@theme contiene animate-fade-in', () => {
    expect(css).toContain('--animate-fade-in:')
  })
})

describe('Fase 1.4 — globals.css con CSS custom properties e classi glow', () => {
  let css: string

  beforeAll(() => {
    css = readFileSync(resolve(ROOT, 'src', 'styles', 'globals.css'), 'utf-8')
  })

  it('globals.css esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'styles', 'globals.css'))).toBe(true)
  })

  it('contiene @import "tailwindcss"', () => {
    expect(css).toContain('@import')
    expect(css).toContain('tailwindcss')
  })

  it('contiene classe .glass', () => {
    expect(css).toContain('.glass')
  })

  it('contiene classe .glass-subtle', () => {
    expect(css).toContain('.glass-subtle')
  })

  it('contiene classe .glow-violet', () => {
    expect(css).toContain('.glow-violet')
  })

  it('contiene classe .glow-magenta', () => {
    expect(css).toContain('.glow-magenta')
  })

  it('contiene classe .glow-blue', () => {
    expect(css).toContain('.glow-blue')
  })

  it('contiene classe .gradient-text', () => {
    expect(css).toContain('.gradient-text')
  })

  it('contiene classe .scrollbar-dark', () => {
    expect(css).toContain('.scrollbar-dark')
  })

  it('contiene CSS custom property --glow-violet', () => {
    expect(css).toContain('--glow-violet')
  })

  it('contiene @custom-variant dark per dark mode class-based', () => {
    expect(css).toContain('@custom-variant dark')
  })

  it('contiene classe .dark per tema scuro', () => {
    expect(css).toContain('.dark')
  })
})

describe('Fase 1.5 — lib/constants.ts e lib/utils.ts', () => {
  it('constants.ts esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'lib', 'constants.ts'))).toBe(true)
  })

  it('constants.ts esporta API_URL', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'constants.ts'))
    expect(mod.API_URL).toBeDefined()
  })

  it('constants.ts esporta ROUTES', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'constants.ts'))
    expect(mod.ROUTES).toBeDefined()
    expect(mod.ROUTES.AUTH).toBeDefined()
    expect(mod.ROUTES.DASHBOARD).toBeDefined()
    expect(mod.ROUTES.ADMIN).toBeDefined()
  })

  it('utils.ts esporta formatDate', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'utils.ts'))
    expect(mod.formatDate).toBeDefined()
    expect(typeof mod.formatDate).toBe('function')
  })

  it('utils.ts esporta formatDateTime', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'utils.ts'))
    expect(mod.formatDateTime).toBeDefined()
    expect(typeof mod.formatDateTime).toBe('function')
  })

  it('utils.ts esporta formatRelativeTime', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'utils.ts'))
    expect(mod.formatRelativeTime).toBeDefined()
    expect(typeof mod.formatRelativeTime).toBe('function')
  })

  it('utils.ts esporta truncate', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'utils.ts'))
    expect(mod.truncate).toBeDefined()
    expect(typeof mod.truncate).toBe('function')
  })
})

describe('Fase 1.6 — lib/api.ts wrapper fetch', () => {
  it('api.ts esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'lib', 'api.ts'))).toBe(true)
  })

  it('api.ts esporta api.get', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(mod.api).toBeDefined()
    expect(typeof mod.api.get).toBe('function')
  })

  it('api.ts esporta api.post', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(typeof mod.api.post).toBe('function')
  })

  it('api.ts esporta api.put', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(typeof mod.api.put).toBe('function')
  })

  it('api.ts esporta api.patch', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(typeof mod.api.patch).toBe('function')
  })

  it('api.ts esporta api.delete', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(typeof mod.api.delete).toBe('function')
  })

  it('api.ts esporta ApiError', async () => {
    const mod = await import(resolve(ROOT, 'src', 'lib', 'api.ts'))
    expect(mod.ApiError).toBeDefined()
  })
})

describe('Fase 1.7 — stores/authStore.ts (Zustand)', () => {
  it('authStore.ts esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'stores', 'authStore.ts'))).toBe(true)
  })

  it('authStore.ts esporta useAuthStore', async () => {
    const mod = await import(resolve(ROOT, 'src', 'stores', 'authStore.ts'))
    expect(mod.useAuthStore).toBeDefined()
    expect(typeof mod.useAuthStore).toBe('function')
  })

  it('useAuthStore ha stato iniziale corretto', async () => {
    const mod = await import(resolve(ROOT, 'src', 'stores', 'authStore.ts'))
    const state = mod.useAuthStore.getState()
    expect(state.isAuthenticated).toBe(false)
    expect(state.user).toBeNull()
  })
})

describe('Fase 1.8 — hooks/useAuth.ts', () => {
  it('useAuth.ts esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'hooks', 'useAuth.ts'))).toBe(true)
  })

  it('useAuth.ts esporta useAuth', async () => {
    const mod = await import(resolve(ROOT, 'src', 'hooks', 'useAuth.ts'))
    expect(mod.useAuth).toBeDefined()
    expect(typeof mod.useAuth).toBe('function')
  })
})

describe('Fase 1.9 — hooks/useApi.ts (TanStack Query)', () => {
  it('useApi.ts esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'hooks', 'useApi.ts'))).toBe(true)
  })

  it('useApi.ts esporta useApiQuery', async () => {
    const mod = await import(resolve(ROOT, 'src', 'hooks', 'useApi.ts'))
    expect(mod.useApiQuery).toBeDefined()
    expect(typeof mod.useApiQuery).toBe('function')
  })

  it('useApi.ts esporta useApiMutation', async () => {
    const mod = await import(resolve(ROOT, 'src', 'hooks', 'useApi.ts'))
    expect(mod.useApiMutation).toBeDefined()
    expect(typeof mod.useApiMutation).toBe('function')
  })

  it('@tanstack/react-query è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('@tanstack/react-query')
  })
})

describe('Fase 1.10 — React Router in App.tsx', () => {
  it('react-router-dom è in dependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.dependencies).toHaveProperty('react-router-dom')
  })

  it('App.tsx esiste', () => {
    expect(existsSync(resolve(ROOT, 'src', 'App.tsx'))).toBe(true)
  })
})

describe('Fase 1.11–1.14 — Componenti layout', () => {
  const LAYOUT_COMPONENTS = ['AppShell', 'Sidebar', 'TopBar', 'PageHeader']

  it.each(LAYOUT_COMPONENTS)('%s.tsx esiste', (name) => {
    expect(existsSync(resolve(ROOT, 'src', 'components', 'layout', `${name}.tsx`))).toBe(true)
  })
})

describe('Fase 1.15 — Shared components', () => {
  const SHARED_COMPONENTS = ['LoadingState', 'ErrorState', 'EmptyState', 'ConfirmDialog']

  it.each(SHARED_COMPONENTS)('%s.tsx esiste', (name) => {
    expect(existsSync(resolve(ROOT, 'src', 'components', 'shared', `${name}.tsx`))).toBe(true)
  })
})

describe('Fase 1.16 — .env frontend', () => {
  it('.env esiste', () => {
    expect(existsSync(resolve(ROOT, '.env'))).toBe(true)
  })

  it('.env contiene VITE_API_URL', () => {
    const envContent = readFileSync(resolve(ROOT, '.env'), 'utf-8')
    expect(envContent).toContain('VITE_API_URL')
  })

  it('.env.example esiste', () => {
    expect(existsSync(resolve(ROOT, '.env.example'))).toBe(true)
  })
})
