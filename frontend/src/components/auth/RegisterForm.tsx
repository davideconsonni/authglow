import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate } from 'react-router-dom'
import { Loader2, Eye, EyeOff, Check, X } from 'lucide-react'
import { api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'
import { cn } from '@/lib/utils'
import { Banner } from '@/components/shared/Banner'
import { FieldError } from '@/components/shared/FieldError'

const registerSchema = z
  .object({
    first_name: z.string().min(1, 'First name is required'),
    last_name: z.string().min(1, 'Last name is required'),
    email: z.string().email('Invalid email address'),
    password: z
      .string()
      .min(12, 'Password must be at least 12 characters')
      .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Must contain at least one digit')
      .regex(/[^A-Za-z0-9]/, 'Must contain at least one special character'),
    confirm_password: z.string(),
  })
  .refine((data) => data.password === data.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })

type RegisterFormData = z.infer<typeof registerSchema>

interface PasswordCheck {
  met: boolean
  label: string
}

function getPasswordChecks(password: string): PasswordCheck[] {
  return [
    { met: password.length >= 12, label: 'At least 12 characters' },
    { met: /[A-Z]/.test(password), label: 'One uppercase letter' },
    { met: /[a-z]/.test(password), label: 'One lowercase letter' },
    { met: /[0-9]/.test(password), label: 'One digit' },
    { met: /[^A-Za-z0-9]/.test(password), label: 'One special character' },
  ]
}

function getPasswordStrength(pw: string): { label: string; width: string; color: string } {
  const checks = getPasswordChecks(pw)
  const met = checks.filter((c) => c.met).length
  if (pw.length === 0) return { label: '', width: '0%', color: '' }
  if (met <= 2) return { label: 'Weak', width: '25%', color: 'bg-semantic-error' }
  if (met <= 3) return { label: 'Fair', width: '50%', color: 'bg-semantic-warning' }
  if (met === 4) return { label: 'Good', width: '75%', color: 'bg-semantic-info' }
  return { label: 'Strong', width: '100%', color: 'bg-semantic-success' }
}

export function RegisterForm() {
  const [showPassword, setShowPassword] = useState(false)
  const [generalError, setGeneralError] = useState('')
  const navigate = useNavigate()

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<RegisterFormData>({
    resolver: zodResolver(registerSchema),
  })

  const password = watch('password', '')
  const checks = getPasswordChecks(password)
  const strength = getPasswordStrength(password)

  const onSubmit = async (data: RegisterFormData) => {
    setGeneralError('')
    try {
      await api.post('/api/users', {
        first_name: data.first_name,
        last_name: data.last_name,
        email: data.email,
        password: data.password,
      })
      navigate(ROUTES.AUTH.LOGIN, {
        state: { registered: true },
      })
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Registration failed. Please try again.')
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {generalError && (
        <Banner variant="error">{generalError}</Banner>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <label htmlFor="first_name" className="block text-sm font-medium text-text-secondary">
            First name
          </label>
          <input
            id="first_name"
            type="text"
            autoComplete="given-name"
            placeholder="John"
            {...register('first_name')}
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
          />
          {errors.first_name && <FieldError id="register-firstname-error">{errors.first_name.message}</FieldError>}
        </div>
        <div className="space-y-2">
          <label htmlFor="last_name" className="block text-sm font-medium text-text-secondary">
            Last name
          </label>
          <input
            id="last_name"
            type="text"
            autoComplete="family-name"
            placeholder="Doe"
            {...register('last_name')}
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
          />
          {errors.last_name && <FieldError id="register-lastname-error">{errors.last_name.message}</FieldError>}
        </div>
      </div>

      <div className="space-y-2">
        <label htmlFor="register-email" className="block text-sm font-medium text-text-secondary">
          Email
        </label>
        <input
          id="register-email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          {...register('email')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.email && <FieldError id="register-email-error">{errors.email.message}</FieldError>}
      </div>

      <div className="space-y-2">
        <label htmlFor="register-password" className="block text-sm font-medium text-text-secondary">
          Password
        </label>
        <div className="relative">
          <input
            id="register-password"
            type={showPassword ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder="Create a strong password"
            {...register('password')}
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 pr-10 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
          />
          <button
            type="button"
            onClick={() => setShowPassword(!showPassword)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
            aria-label={showPassword ? 'Hide password' : 'Show password'}
          >
            {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
          </button>
        </div>

        {/* Password strength meter */}
        {password && (
          <div className="space-y-2">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-2">
              <div
                className={cn('h-full rounded-full transition-all duration-300', strength.color)}
                style={{ width: strength.width }}
              />
            </div>
            <p className="text-xs text-text-muted">
              Strength: <span className="font-medium text-text-secondary">{strength.label}</span>
            </p>
            <ul className="space-y-1">
              {checks.map((check) => (
                <li key={check.label} className="flex items-center gap-1.5 text-xs text-text-muted">
                  {check.met ? (
                    <Check size={12} className="text-semantic-success" />
                  ) : (
                    <X size={12} className="text-surface-3" />
                  )}
                  {check.label}
                </li>
              ))}
            </ul>
          </div>
        )}

        {errors.password && <FieldError id="register-password-error">{errors.password.message}</FieldError>}
      </div>

      <div className="space-y-2">
        <label htmlFor="confirm_password" className="block text-sm font-medium text-text-secondary">
          Confirm password
        </label>
        <input
          id="confirm_password"
          type="password"
          autoComplete="new-password"
          placeholder="Confirm your password"
          {...register('confirm_password')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.confirm_password && <FieldError id="register-confirm-error">{errors.confirm_password.message}</FieldError>}
      </div>

      <button
        type="submit"
        disabled={isSubmitting}
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {isSubmitting ? 'Creating account...' : 'Create account'}
      </button>
    </form>
  )
}
