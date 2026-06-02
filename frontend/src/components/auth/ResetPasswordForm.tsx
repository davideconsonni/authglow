import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useSearchParams, Link } from 'react-router-dom'
import { Loader2, Eye, EyeOff, AlertCircle, ShieldCheck } from 'lucide-react'
import { api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'

const resetPasswordSchema = z
  .object({
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

type ResetPasswordFormData = z.infer<typeof resetPasswordSchema>

export function ResetPasswordForm() {
  const [showPassword, setShowPassword] = useState(false)
  const [generalError, setGeneralError] = useState('')
  const [success, setSuccess] = useState(false)
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ResetPasswordFormData>({
    resolver: zodResolver(resetPasswordSchema),
  })

  const onSubmit = async (data: ResetPasswordFormData) => {
    setGeneralError('')
    try {
      await api.post('/api/password/reset/confirm', {
        token,
        new_password: data.password,
      })
      setSuccess(true)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Password reset failed. Please try again.')
    }
  }

  if (!token) {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-error/10">
          <AlertCircle className="h-7 w-7 text-semantic-error" />
        </div>
        <h3 className="text-lg font-semibold text-text-primary">Invalid reset link</h3>
        <p className="text-sm text-text-muted">
          This password reset link is invalid or has expired. Please request a new one.
        </p>
        <Link
          to={ROUTES.AUTH.FORGOT_PASSWORD}
          className="inline-block text-sm font-medium text-brand-violet hover:text-brand-blue transition-colors"
        >
          Request a new reset link
        </Link>
      </div>
    )
  }

  if (success) {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
          <ShieldCheck className="h-7 w-7 text-semantic-success" />
        </div>
        <h3 className="text-lg font-semibold text-text-primary">Password reset successful</h3>
        <p className="text-sm text-text-muted">
          Your password has been changed. You can now sign in with your new password.
        </p>
        <Link
          to={ROUTES.AUTH.LOGIN}
          className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          Sign in
        </Link>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {generalError && (
        <div className="rounded-xl border border-semantic-error/30 bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">
          {generalError}
        </div>
      )}

      <div className="space-y-2">
        <label htmlFor="new-password" className="block text-sm font-medium text-text-secondary">
          New password
        </label>
        <div className="relative">
          <input
            id="new-password"
            type={showPassword ? 'text' : 'password'}
            autoComplete="new-password"
            placeholder="Enter new password"
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
        {errors.password && (
          <p className="text-xs text-semantic-error" role="alert">{errors.password.message}</p>
        )}
      </div>

      <div className="space-y-2">
        <label htmlFor="confirm-new-password" className="block text-sm font-medium text-text-secondary">
          Confirm new password
        </label>
        <input
          id="confirm-new-password"
          type="password"
          autoComplete="new-password"
          placeholder="Confirm new password"
          {...register('confirm_password')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.confirm_password && (
          <p className="text-xs text-semantic-error" role="alert">{errors.confirm_password.message}</p>
        )}
      </div>

      <button
        type="submit"
        disabled={isSubmitting}
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {isSubmitting ? 'Resetting...' : 'Reset password'}
      </button>
    </form>
  )
}
