import { Sun, Moon, type LucideIcon } from 'lucide-react'
import { useTheme, type Theme } from '../../hooks/useTheme'
import { cn } from '../../lib/utils'

const THEME_OPTIONS: Array<{ value: Theme; label: string; icon: LucideIcon; testId: string }> = [
  { value: 'professional', label: 'Light theme', icon: Sun, testId: 'theme-professional' },
  { value: 'dark', label: 'Dark theme', icon: Moon, testId: 'theme-dark' },
]

interface ThemeSwitcherProps {
  /** 'md' = TopBar size, 'sm' = compact (standalone pages). */
  size?: 'sm' | 'md'
  className?: string
}

export function ThemeSwitcher({ size = 'md', className }: ThemeSwitcherProps) {
  const { theme, setTheme } = useTheme()

  return (
    <div className={cn('flex items-center gap-1', className)} role="group" aria-label="Color theme">
      {THEME_OPTIONS.map(({ value, label, icon: Icon, testId }) => (
        <button
          key={value}
          type="button"
          onClick={() => setTheme(value)}
          aria-label={label}
          aria-pressed={theme === value}
          data-testid={testId}
          className={cn(
            'rounded-xl transition-colors',
            size === 'sm' ? 'p-1.5' : 'p-2',
            theme === value
              ? 'bg-surface-2 text-brand-accent'
              : 'text-text-muted hover:bg-surface-2 hover:text-text-secondary',
          )}
        >
          <Icon size={size === 'sm' ? 16 : 18} />
        </button>
      ))}
    </div>
  )
}
