import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useLocation, useNavigate } from 'react-router-dom'
import { Loader2, Eye, EyeOff, ShieldCheck } from 'lucide-react'
import { api } from '../../lib/api'
import { ROUTES } from '../../lib/constants'
import { Banner } from '../../components/shared/Banner'
import { FieldError } from '../../components/shared/FieldError'
import { AuthLayout } from '../../components/auth/AuthLayout'
import { notify } from '../../stores/toastStore'

const forceChangePasswordSchema = z
  .object({
    current_password: z.string().min(1, 'Enter your current password'),
    new_password: z
      .string()
      .min(12, 'Password must be at least 12 characters')
      .regex(/[A-Z]/, 'Must contain at least one uppercase letter')
      .regex(/[a-z]/, 'Must contain at least one lowercase letter')
      .regex(/[0-9]/, 'Must contain at least one digit')
      .regex(/[^A-Za-z0-9]/, 'Must contain at least one special character'),
    confirm_password: z.string(),
  })
  .refine((data) => data.new_password === data.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })

type ForceChangePasswordFormData = z.infer<typeof forceChangePasswordSchema>

export function ForceChangePasswordPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const email = (location.state as { email?: string } | null)?.email ?? ''
  const [showPassword, setShowPassword] = useState(false)
  const [generalError, setGeneralError] = useState('')
  const [success, setSuccess] = useState(false)

  useEffect(() => {
    if (!email) navigate(ROUTES.AUTH.LOGIN, { replace: true })
  }, [email, navigate])

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForceChangePasswordFormData>({
    resolver: zodResolver(forceChangePasswordSchema),
  })

  const onSubmit = async (data: ForceChangePasswordFormData) => {
    setGeneralError('')
    try {
      await api.post('/api/auth/expired-password/change', {
        email,
        current_password: data.current_password,
        new_password: data.new_password,
      })
      setSuccess(true)
      notify.success('Password updated. You can now sign in.')
      setTimeout(() => navigate(ROUTES.AUTH.LOGIN, { replace: true }), 1500)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      if (/not required/i.test(message)) {
        // The flag was already cleared — just go sign in.
        navigate(ROUTES.AUTH.LOGIN, { replace: true })
        return
      }
      setGeneralError(message || 'Password change failed. Please try again.')
    }
  }

  return (
    <AuthLayout
      title="Update expired password"
      description={`The password for ${email} has expired. Choose a new one to continue.`}
    >
      {success ? (
        <div className="space-y-4 text-center" data-testid="force-change-success">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
            <ShieldCheck className="h-7 w-7 text-semantic-success" />
          </div>
          <h3 className="text-lg font-semibold text-text-primary">Password updated</h3>
          <p className="text-sm text-text-muted">
            Your password has been changed. Redirecting you to sign in...
          </p>
        </div>
      ) : (
        <form
          onSubmit={handleSubmit(onSubmit)}
          className="space-y-5"
          data-testid="force-change-form"
        >
          {generalError && (
            <Banner variant="error" role="alert">
              {generalError}
            </Banner>
          )}

          <div className="space-y-2">
            <label
              htmlFor="current-password"
              className="block text-sm font-medium text-text-secondary"
            >
              Current password
            </label>
            <input
              id="current-password"
              type="password"
              autoComplete="current-password"
              placeholder="Enter current password"
              data-testid="force-change-current"
              {...register('current_password')}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 transition-colors"
            />
            {errors.current_password && (
              <FieldError id="force-change-current-error">
                {errors.current_password.message}
              </FieldError>
            )}
          </div>

          <div className="space-y-2">
            <label
              htmlFor="expired-new-password"
              className="block text-sm font-medium text-text-secondary"
            >
              New password
            </label>
            <div className="relative">
              <input
                id="expired-new-password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder="Enter new password"
                data-testid="force-change-new"
                {...register('new_password')}
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 pr-10 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 transition-colors"
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
            {errors.new_password && (
              <FieldError id="force-change-new-error">{errors.new_password.message}</FieldError>
            )}
          </div>

          <div className="space-y-2">
            <label
              htmlFor="expired-confirm-password"
              className="block text-sm font-medium text-text-secondary"
            >
              Confirm new password
            </label>
            <input
              id="expired-confirm-password"
              type="password"
              autoComplete="new-password"
              placeholder="Confirm new password"
              data-testid="force-change-confirm"
              {...register('confirm_password')}
              className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20 transition-colors"
            />
            {errors.confirm_password && (
              <FieldError id="force-change-confirm-error">
                {errors.confirm_password.message}
              </FieldError>
            )}
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            data-testid="force-change-submit"
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-accent transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed btn-cta"
          >
            {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            {isSubmitting ? 'Updating...' : 'Update password'}
          </button>
        </form>
      )}
    </AuthLayout>
  )
}
