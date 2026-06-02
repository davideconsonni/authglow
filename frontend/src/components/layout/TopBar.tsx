import { useNavigate } from 'react-router-dom'
import { LogOut, User, ChevronDown, Sun, Moon } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { useTheme } from '@/hooks/useTheme'
import { ROUTES } from '@/lib/constants'
import { useEffect, useState } from 'react'

export function TopBar() {
  const { user, logout } = useAuth()
  const { toggleTheme } = useTheme()
  const navigate = useNavigate()
  const [isLight, setIsLight] = useState(false)

  useEffect(() => {
    setIsLight(document.documentElement.classList.contains('light'))
    const observer = new MutationObserver(() => {
      setIsLight(document.documentElement.classList.contains('light'))
    })
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
    return () => observer.disconnect()
  }, [])

  const handleLogout = () => {
    logout()
    navigate(ROUTES.AUTH.LOGIN)
  }

  return (
    <header className="flex h-16 items-center justify-between border-b border-surface-2 bg-surface-1 px-6">
      <div />

      <div className="flex items-center gap-2">
        <button
          onClick={toggleTheme}
          className="rounded-xl p-2 text-text-muted hover:bg-surface-2 hover:text-text-secondary transition-colors"
          aria-label={isLight ? 'Switch to dark mode' : 'Switch to light mode'}
        >
          {isLight ? <Moon size={18} /> : <Sun size={18} />}
        </button>
        <div className="dropdown">
          <button
            className="flex items-center gap-2 rounded-xl px-3 py-1.5 text-sm text-text-secondary hover:bg-surface-2 transition-colors"
            onClick={(e) => {
              const menu = e.currentTarget.nextElementSibling
              if (menu) menu.classList.toggle('hidden')
            }}
          >
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-brand-violet/20 text-brand-violet text-sm font-medium">
              {user?.first_name?.charAt(0) || 'U'}
            </div>
            <span className="hidden sm:inline">
              {user ? `${user.first_name} ${user.last_name}` : 'User'}
            </span>
            <ChevronDown size={14} />
          </button>
          <div className="absolute right-6 top-14 z-50 mt-1 hidden w-48 rounded-xl border border-surface-2 bg-surface-1 shadow-glow-violet">
            <button
              onClick={() => navigate(ROUTES.PROFILE)}
              className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-text-secondary hover:bg-surface-2 hover:text-text-primary transition-colors rounded-t-xl"
            >
              <User size={16} />
              Profile
            </button>
            <button
              onClick={handleLogout}
              data-testid="logout-btn"
              className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-semantic-error hover:bg-surface-2 transition-colors rounded-b-xl"
            >
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>
      </div>
    </header>
  )
}
