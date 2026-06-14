import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Mail, ArrowLeft } from 'lucide-react'
import { api } from '@/lib/api'
import { Banner } from '@/components/shared/Banner'
import { FieldError } from '@/components/shared/FieldError'

const forgotPasswordSchema = z.object({
  email: z.string().email('Invalid email address'),
})

type ForgotPasswordFormData = z.infer<typeof forgotPasswordSchema>

export function ForgotPasswordForm() {
  const [sent, setSent] = useState(false)
  const [generalError, setGeneralError] = useState('')

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<ForgotPasswordFormData>({
    resolver: zodResolver(forgotPasswordSchema),
  })

  const onSubmit = async (data: ForgotPasswordFormData) => {
    setGeneralError('')
    try {
      await api.post('/api/password/reset/request', { email: data.email })
      setSent(true)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setGeneralError(message || 'Something went wrong. Please try again.')
    }
  }

  if (sent) {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
          <Mail className="h-7 w-7 text-semantic-success" />
        </div>
        <h3 className="text-lg font-semibold text-text-primary">Check your email</h3>
        <p className="text-sm text-text-muted">
          If an account with that email exists, we've sent a password reset link. Please check your inbox and spam folder.
        </p>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {generalError && (
        <Banner variant="error">{generalError}</Banner>
      )}

      <div className="space-y-2">
        <label htmlFor="reset-email" className="block text-sm font-medium text-text-secondary">
          Email address
        </label>
        <input
          id="reset-email"
          type="email"
          autoComplete="email"
          placeholder="you@example.com"
          {...register('email')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.email && <FieldError id="forgot-email-error">{errors.email.message}</FieldError>}
      </div>

      <button
        type="submit"
        disabled={isSubmitting}
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        {isSubmitting ? 'Sending...' : 'Send reset link'}
      </button>
    </form>
  )
}

export function BackToLoginLink() {
  return (
    <a
      href="/auth/login"
      className="inline-flex items-center gap-1.5 text-sm text-text-muted hover:text-text-secondary transition-colors"
    >
      <ArrowLeft size={14} />
      Back to login
    </a>
  )
}
