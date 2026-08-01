import { useState, useEffect, useRef, useCallback } from 'react'
import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  User,
  Shield,
  Monitor,
  Key,
  Settings,
  Users,
  Server,
  Activity,
  FileCheck,
  Lock,
  Play,
  Menu,
  X,
  Globe,
  Smartphone,
  SlidersHorizontal,
  Gauge,
  type LucideIcon,
} from 'lucide-react'
import { ROUTES } from '../../lib/constants'
import { cn } from '../../lib/utils'
import { useAuth } from '../../hooks/useAuth'

interface NavSection {
  label: string
  items: NavItem[]
}

interface NavItem {
  label: string
  icon: LucideIcon
  to: string
}

export function Sidebar() {
  const [isMobileOpen, setMobileOpen] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const { user } = useAuth()
  const mobileNavRef = useRef<HTMLElement>(null)
  const previousFocusRef = useRef<HTMLElement | null>(null)

  const isAdmin = user?.scopes?.includes('admin')

  const sections: NavSection[] = [
    {
      label: 'Account',
      items: [
        { label: 'Dashboard', icon: LayoutDashboard, to: ROUTES.DASHBOARD },
        { label: 'Profile', icon: User, to: ROUTES.PROFILE },
        { label: 'Security', icon: Shield, to: ROUTES.SECURITY },
        { label: 'Sessions', icon: Monitor, to: ROUTES.SESSIONS },
        { label: 'API Keys', icon: Key, to: ROUTES.API_KEYS },
        { label: 'Device Auths', icon: Smartphone, to: ROUTES.DEVICE_AUTHORIZATIONS },
      ],
    },
  ]

  if (isAdmin) {
    sections.push({
      label: 'Administration',
      items: [
        { label: 'Overview', icon: Settings, to: ROUTES.ADMIN.DASHBOARD },
        { label: 'Users', icon: Users, to: ROUTES.ADMIN.USERS },
        { label: 'OAuth Clients', icon: Server, to: ROUTES.ADMIN.OAUTH_CLIENTS },
        { label: 'Sessions', icon: Activity, to: ROUTES.ADMIN.SESSIONS },
        { label: 'Consents', icon: FileCheck, to: ROUTES.ADMIN.CONSENTS },
        { label: 'API Keys', icon: Key, to: ROUTES.ADMIN.API_KEYS },
        { label: 'RBAC', icon: Lock, to: ROUTES.ADMIN.RBAC },
        { label: 'JWK Keys', icon: Shield, to: ROUTES.ADMIN.JWK_KEYS },
        { label: 'Password Resets', icon: Lock, to: ROUTES.ADMIN.PASSWORD_RESETS },
        { label: 'Playground', icon: Play, to: ROUTES.ADMIN.PLAYGROUND },
        { label: 'Federation', icon: Globe, to: ROUTES.ADMIN.FEDERATION },
        { label: 'Device Auths', icon: Smartphone, to: ROUTES.ADMIN.DEVICE_AUTHORIZATIONS },
        { label: 'Settings', icon: SlidersHorizontal, to: ROUTES.ADMIN.SETTINGS },
        { label: 'Rate Limits', icon: Gauge, to: ROUTES.ADMIN.RATE_LIMITS },
      ],
    })
  }

  const closeMobile = useCallback(() => {
    setMobileOpen(false)
    previousFocusRef.current?.focus()
  }, [])

  // Escape key handler + focus trap for mobile sidebar
  useEffect(() => {
    if (!isMobileOpen) return

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeMobile()
        return
      }

      // Focus trap
      if (e.key === 'Tab' && mobileNavRef.current) {
        const focusable = mobileNavRef.current.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )
        if (focusable.length === 0) return

        const first = focusable[0]
        const last = focusable[focusable.length - 1]

        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault()
          last.focus()
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    // Auto-focus first nav item
    requestAnimationFrame(() => {
      const firstLink = mobileNavRef.current?.querySelector<HTMLElement>('a[href]')
      firstLink?.focus()
    })

    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [isMobileOpen, closeMobile])

  // Lock body scroll when mobile sidebar is open
  useEffect(() => {
    if (isMobileOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [isMobileOpen])

  const openMobile = () => {
    previousFocusRef.current = document.activeElement as HTMLElement
    setMobileOpen(true)
  }

  const sidebarContent = (isMobile: boolean) => (
    <div
      className={cn(
        'flex h-full flex-col bg-surface-1 border-r border-surface-2 transition-all duration-300 scrollbar-dark',
        collapsed && !isMobile ? 'w-16' : 'w-64',
      )}
    >
      <div className="flex h-16 items-center justify-between px-4 border-b border-surface-2">
        {!collapsed && (
          <span className="text-lg font-bold gradient-text">AuthGlow</span>
        )}
        {!isMobile && (
          <button
            onClick={() => setCollapsed(!collapsed)}
            className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary transition-colors"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            <Menu size={18} />
          </button>
        )}
        {isMobile && (
          <button
            onClick={closeMobile}
            className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary transition-colors"
            aria-label="Close sidebar"
          >
            <X size={18} />
          </button>
        )}
      </div>

      <nav ref={isMobile ? mobileNavRef : undefined} className="flex-1 overflow-y-auto py-4 space-y-6">
        {sections.map((section) => (
          <div key={section.label} className="px-3">
            {!collapsed && (
              <h3 className="mb-2 px-4 text-xs font-semibold tracking-wider text-text-muted uppercase">
                {section.label}
              </h3>
            )}
            <ul className="space-y-1">
                {section.items.map((item) => {
                    const isTopLevel = ['/dashboard', '/admin'].includes(item.to)
                    return (
                    <li key={item.to}>
                      <NavLink
                        to={item.to}
                        end={isTopLevel}
                        onClick={isMobile ? closeMobile : undefined}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-3 rounded-xl px-3 min-h-[44px] py-2.5 text-sm font-medium transition-all duration-150',
                        isActive
                          ? 'bg-brand-violet/15 text-brand-violet shadow-glow-violet'
                          : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
                        collapsed && !isMobile && 'justify-center px-2',
                      )
                    }
                    title={collapsed && !isMobile ? item.label : undefined}
                  >
                    <item.icon size={20} />
                    {!collapsed && <span>{item.label}</span>}
                  </NavLink>
                </li>
              )})}
            </ul>
          </div>
        ))}
      </nav>
    </div>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden md:block" data-testid="sidebar">{sidebarContent(false)}</aside>

      {/* Mobile toggle */}
      <button
        onClick={openMobile}
        className="fixed top-4 left-4 z-30 rounded-xl p-2 bg-surface-1 border border-surface-2 text-text-secondary md:hidden"
        aria-label="Open sidebar"
      >
        <Menu size={20} />
      </button>

      {/* Mobile sidebar */}
      <div
        className={cn(
          'fixed inset-0 z-50 md:hidden transition-opacity duration-300',
          isMobileOpen ? 'opacity-100 pointer-events-auto' : 'opacity-0 pointer-events-none',
        )}
      >
        {/* Backdrop */}
        <div
          className={cn(
            'absolute inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-300',
            isMobileOpen ? 'opacity-100' : 'opacity-0',
          )}
          onClick={closeMobile}
          aria-hidden="true"
        />

        {/* Panel */}
        <aside
          className={cn(
            'absolute inset-y-0 left-0 z-50 transition-transform duration-300 ease-out',
            isMobileOpen ? 'translate-x-0' : '-translate-x-full',
          )}
          role="dialog"
          aria-modal="true"
          aria-label="Navigation menu"
        >
          {sidebarContent(true)}
        </aside>
      </div>
    </>
  )
}
