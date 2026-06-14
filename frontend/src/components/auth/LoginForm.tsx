import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Loader2, Eye, EyeOff } from 'lucide-react'
import { useAuth } from '@/hooks/useAuth'
import { ROUTES } from '@/lib/constants'
import { getSavedEmail, saveEmail } from '@/lib/loginStorage'
import { Banner } from '@/components/shared/Banner'
import { FieldError } from '@/components/shared/FieldError'

const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

type LoginFormData = z.infer<typeof loginSchema>

export function LoginForm() {
  const [showPassword, setShowPassword] = useState(false)
  const [generalError, setGeneralError] = useState('')
  const { login } = useAuth()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const redirect = searchParams.get('redirect')

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: getSavedEmail() },
  })

  const onSubmit = async (data: LoginFormData) => {
    setGeneralError('')
    try {
      const result = await login(data.email, data.password)

      saveEmail(data.email)

      if ('mfa_required' in result && result.mfa_required) {
        const sessionToken = result as unknown as { session_token: string }
        navigate(`/auth/mfa-verify?session_token=${sessionToken.session_token}`)
        return
      }

      if (redirect) {
        window.location.assign(redirect)
        return
      }

      navigate(ROUTES.DASHBOARD)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      if (message.includes('423') || message.includes('locked')) {
        setGeneralError('Account temporarily locked. Please try again later.')
      } else if (message.includes('401') || message.includes('Unauthorized')) {
        setGeneralError('Invalid email or password.')
      } else {
        setGeneralError(message || 'Login failed. Please try again.')
      }
    }
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {generalError && (
        <Banner variant="error" role="alert">
          {generalError}
        </Banner>
      )}

      <div className="space-y-2">
        <label htmlFor="email" className="block text-sm font-medium text-text-secondary">
          Email
        </label>
        <input
          id="email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          data-testid="login-email"
          {...register('email')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.email && <FieldError id="login-email-error">{errors.email.message}</FieldError>}
      </div>

      <div className="space-y-2">
        <label htmlFor="password" className="block text-sm font-medium text-text-secondary">
          Password
        </label>
        <div className="relative">
          <input
            id="password"
            type={showPassword ? 'text' : 'password'}
            autoComplete="current-password"
            placeholder="Enter your password"
            data-testid="login-password"
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
        {errors.password && <FieldError id="login-password-error">{errors.password.message}</FieldError>}
      </div>

      <button
        type="submit"
        disabled={isSubmitting}
        data-testid="login-submit"
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {isSubmitting ? 'Signing in...' : 'Sign in'}
      </button>
    </form>
  )
}
