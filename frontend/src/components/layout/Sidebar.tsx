import { useState } from 'react'
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
  type LucideIcon,
} from 'lucide-react'
import { ROUTES } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { useAuth } from '@/hooks/useAuth'

interface NavSection {
  label: string
  items: NavItem[]
  adminOnly?: boolean
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

  const isAdmin = user?.roles?.includes('admin') || user?.scopes?.includes('admin')

  const sections: NavSection[] = [
    {
      label: 'Main',
      items: [
        { label: 'Dashboard', icon: LayoutDashboard, to: ROUTES.DASHBOARD },
        { label: 'Profile', icon: User, to: ROUTES.PROFILE },
        { label: 'Security', icon: Shield, to: ROUTES.SECURITY },
        { label: 'Sessions', icon: Monitor, to: ROUTES.SESSIONS },
        { label: 'API Keys', icon: Key, to: ROUTES.API_KEYS },
      ],
    },
    {
      label: 'Administration',
      adminOnly: true,
      items: [
        { label: 'Admin Dashboard', icon: Settings, to: ROUTES.ADMIN.DASHBOARD },
        { label: 'Users', icon: Users, to: ROUTES.ADMIN.USERS },
        { label: 'OAuth Clients', icon: Server, to: ROUTES.ADMIN.OAUTH_CLIENTS },
        { label: 'Sessions', icon: Activity, to: ROUTES.ADMIN.SESSIONS },
        { label: 'Consents', icon: FileCheck, to: ROUTES.ADMIN.CONSENTS },
        { label: 'RBAC', icon: Lock, to: ROUTES.ADMIN.RBAC },
        { label: 'API Keys', icon: Key, to: ROUTES.ADMIN.API_KEYS },
        { label: 'JWK Keys', icon: Shield, to: ROUTES.ADMIN.JWK_KEYS },
        { label: 'Password Resets', icon: Lock, to: ROUTES.ADMIN.PASSWORD_RESETS },
        { label: 'Playground', icon: Play, to: ROUTES.ADMIN.PLAYGROUND },
      ],
    },
  ]

  const visibleSections = sections.filter((s) => !s.adminOnly || isAdmin)

  const sidebarContent = (
    <div
      className={cn(
        'flex h-full flex-col bg-surface-1 border-r border-surface-2 transition-all duration-300 scrollbar-dark',
        collapsed ? 'w-16' : 'w-64',
      )}
    >
      <div className="flex h-16 items-center justify-between px-4 border-b border-surface-2">
        {!collapsed && (
          <span className="text-lg font-bold gradient-text">AuthGlow</span>
        )}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="rounded-lg p-1.5 text-text-muted hover:bg-surface-2 hover:text-text-secondary transition-colors"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          <Menu size={18} />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto py-4 space-y-6">
        {visibleSections.map((section) => (
          <div key={section.label} className="px-3">
            {!collapsed && (
              <h3 className="mb-2 px-4 text-xs font-semibold tracking-wider text-text-muted uppercase">
                {section.label}
              </h3>
            )}
            <ul className="space-y-1">
              {section.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    className={({ isActive }) =>
                      cn(
                        'flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-150',
                        isActive
                          ? 'bg-brand-violet/15 text-brand-violet shadow-glow-violet'
                          : 'text-text-secondary hover:bg-surface-2 hover:text-text-primary',
                        collapsed && 'justify-center px-2',
                      )
                    }
                    title={collapsed ? item.label : undefined}
                  >
                    <item.icon size={20} />
                    {!collapsed && <span>{item.label}</span>}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
    </div>
  )

  return (
    <>
      {/* Desktop sidebar */}
      <aside className="hidden md:block">{sidebarContent}</aside>

      {/* Mobile sidebar overlay */}
      {isMobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Mobile sidebar */}
      {isMobileOpen && (
        <aside className="fixed inset-y-0 left-0 z-50 md:hidden">
          {sidebarContent}
        </aside>
      )}

      {/* Mobile toggle */}
      <button
        onClick={() => setMobileOpen(true)}
        className="fixed top-4 left-4 z-30 rounded-xl p-2 bg-surface-1 border border-surface-2 text-text-secondary md:hidden"
        aria-label="Open sidebar"
      >
        <Menu size={20} />
      </button>

      {/* Mobile close button */}
      {isMobileOpen && (
        <button
          onClick={() => setMobileOpen(false)}
          className="fixed top-4 left-[calc(16rem+1rem)] z-50 rounded-xl p-2 bg-surface-1 border border-surface-2 text-text-secondary md:hidden"
          aria-label="Close sidebar"
        >
          <X size={20} />
        </button>
      )}
    </>
  )
}
