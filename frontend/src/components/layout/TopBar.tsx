import { useNavigate } from 'react-router-dom'
import { LogOut, User } from 'lucide-react'
import { useAuth } from '../../hooks/useAuth'
import { ROUTES } from '../../lib/constants'
import { ThemeSwitcher } from '../../components/shared/ThemeSwitcher'
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from '../../components/ui/dropdown-menu'

export function TopBar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate(ROUTES.AUTH.LOGIN, { replace: true })
  }

  return (
    <header className="topbar-shell flex h-16 items-center justify-between border-b border-surface-2 bg-surface-1 px-6">
      <div />

      <div className="flex items-center gap-2">
        <ThemeSwitcher />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              className="flex items-center gap-2 rounded-xl px-3 py-1.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors outline-none"
              data-testid="user-menu-trigger"
            >
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-surface-2 text-text-secondary text-sm font-medium">
                {user?.first_name?.charAt(0) || 'U'}
              </div>
              <span className="hidden sm:inline">
                {user ? `${user.first_name} ${user.last_name}` : 'User'}
              </span>
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-text-muted">
                <path d="M3.5 5.25L7 8.75L10.5 5.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            align="end"
            sideOffset={8}
            className="w-48 rounded-xl border border-surface-2 bg-surface-1 shadow-glow-accent"
          >
            <DropdownMenuItem
              onClick={() => navigate(ROUTES.PROFILE)}
              className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-text-secondary cursor-pointer focus:bg-surface-2 focus:text-text-primary"
            >
              <User size={16} />
              Profile
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-surface-2" />
            <DropdownMenuItem
              onClick={handleLogout}
              data-testid="logout-btn"
              className="flex items-center gap-2 rounded-lg px-3 py-2.5 text-sm text-semantic-error cursor-pointer focus:bg-surface-2 focus:text-semantic-error"
            >
              <LogOut size={16} />
              Logout
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
