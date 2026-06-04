import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync, existsSync } from 'node:fs'
import { resolve } from 'node:path'

const ROOT = resolve(import.meta.dirname, '..')

function readPackageJson() {
  return JSON.parse(readFileSync(resolve(ROOT, 'package.json'), 'utf-8'))
}

describe('Fase 1.1 — Tailwind CSS + PostCSS + Autoprefixer', () => {
  it('tailwindcss è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('tailwindcss')
  })

  it('postcss è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('postcss')
  })

  it('autoprefixer è in devDependencies', () => {
    const pkg = readPackageJson()
    expect(pkg.devDependencies).toHaveProperty('autoprefixer')
  })

  it('postcss.config.js esiste', () => {
    const configPath = resolve(ROOT, 'postcss.config.js')
    expect(existsSync(configPath)).toBe(true)
  })

  it('postcss.config.js contiene la configurazione tailwindcss', async () => {
    const config = await import(resolve(ROOT, 'postcss.config.js'))
    expect(config.default.plugins).toHaveProperty('tailwindcss')
  })

  it('postcss.config.js contiene la configurazione autoprefixer', async () => {
    const config = await import(resolve(ROOT, 'postcss.config.js'))
    expect(config.default.plugins).toHaveProperty('autoprefixer')
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

describe('Fase 1.3 — Design token AuthGlow in tailwind.config.js', () => {
  let config: Record<string, unknown>

  beforeAll(async () => {
    config = (await import(resolve(ROOT, 'tailwind.config.js'))).default
  })

  it('tailwind.config.js esiste ed è importabile', () => {
    expect(config).toBeDefined()
  })

  describe('Colori bg', () => {
    it('bg.primary usa CSS variable', () => {
      expect(config.theme.extend.colors.bg.primary).toBe('var(--color-bg-primary)')
    })
    it('bg.secondary usa CSS variable', () => {
      expect(config.theme.extend.colors.bg.secondary).toBe('var(--color-bg-secondary)')
    })
    it('bg.tertiary usa CSS variable', () => {
      expect(config.theme.extend.colors.bg.tertiary).toBe('var(--color-bg-tertiary)')
    })
  })

  describe('Colori surface', () => {
    it('surface.1 usa CSS variable', () => {
      expect(config.theme.extend.colors.surface['1']).toBe('var(--color-surface-1)')
    })
    it('surface.2 usa CSS variable', () => {
      expect(config.theme.extend.colors.surface['2']).toBe('var(--color-surface-2)')
    })
    it('surface.3 usa CSS variable', () => {
      expect(config.theme.extend.colors.surface['3']).toBe('var(--color-surface-3)')
    })
  })

  describe('Colori brand', () => {
    it('brand.violet usa CSS variable', () => {
      expect(config.theme.extend.colors.brand.violet).toBe('var(--color-brand-violet)')
    })
    it('brand.magenta usa CSS variable', () => {
      expect(config.theme.extend.colors.brand.magenta).toBe('var(--color-brand-magenta)')
    })
    it('brand.blue usa CSS variable', () => {
      expect(config.theme.extend.colors.brand.blue).toBe('var(--color-brand-blue)')
    })
  })

  describe('Colori semantic', () => {
    it('semantic.success usa CSS variable', () => {
      expect(config.theme.extend.colors.semantic.success).toBe('var(--color-semantic-success)')
    })
    it('semantic.warning usa CSS variable', () => {
      expect(config.theme.extend.colors.semantic.warning).toBe('var(--color-semantic-warning)')
    })
    it('semantic.error usa CSS variable', () => {
      expect(config.theme.extend.colors.semantic.error).toBe('var(--color-semantic-error)')
    })
    it('semantic.info usa CSS variable', () => {
      expect(config.theme.extend.colors.semantic.info).toBe('var(--color-semantic-info)')
    })
  })

  describe('Colori text', () => {
    it('text.primary usa CSS variable', () => {
      expect(config.theme.extend.colors.text.primary).toBe('var(--color-text-primary)')
    })
    it('text.secondary usa CSS variable', () => {
      expect(config.theme.extend.colors.text.secondary).toBe('var(--color-text-secondary)')
    })
    it('text.muted usa CSS variable', () => {
      expect(config.theme.extend.colors.text.muted).toBe('var(--color-text-muted)')
    })
  })

  describe('Font family', () => {
    it('include Inter', () => {
      expect(config.theme.extend.fontFamily.sans).toContain('Inter')
    })
  })

  describe('Glow shadows', () => {
    it('glow-violet definito', () => {
      expect(config.theme.extend.boxShadow['glow-violet']).toBeDefined()
    })
    it('glow-magenta definito', () => {
      expect(config.theme.extend.boxShadow['glow-magenta']).toBeDefined()
    })
    it('glow-blue definito', () => {
      expect(config.theme.extend.boxShadow['glow-blue']).toBeDefined()
    })
  })

  describe('Gradient background', () => {
    it('gradient-cta definito', () => {
      expect(config.theme.extend.backgroundImage['gradient-cta']).toBeDefined()
    })
    it('gradient-secondary definito', () => {
      expect(config.theme.extend.backgroundImage['gradient-secondary']).toBeDefined()
    })
  })

  describe('Border radius', () => {
    it('card radius = 24px', () => {
      expect(config.theme.extend.borderRadius.card).toBe('24px')
    })
  })

  describe('Transition durations', () => {
    it('micro = 150ms', () => {
      expect(config.theme.extend.transitionDuration.micro).toBe('150ms')
    })
    it('complex = 400ms', () => {
      expect(config.theme.extend.transitionDuration.complex).toBe('400ms')
    })
    it('page = 500ms', () => {
      expect(config.theme.extend.transitionDuration.page).toBe('500ms')
    })
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

  it('contiene @tailwind base', () => {
    expect(css).toContain('@tailwind base')
  })

  it('contiene @tailwind components', () => {
    expect(css).toContain('@tailwind components')
  })

  it('contiene @tailwind utilities', () => {
    expect(css).toContain('@tailwind utilities')
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
