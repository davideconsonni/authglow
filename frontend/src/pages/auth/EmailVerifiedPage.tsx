import { useSearchParams, Link } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { MailCheck, AlertCircle, Loader2, RefreshCw, KeyRound } from 'lucide-react'
import { ApiError, api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'
import { Banner } from '@/components/shared/Banner'
import { FieldError } from '@/components/shared/FieldError'

const verificationCodeSchema = z.object({
  verification_code: z
    .string()
    .min(14, 'Verification code must be 14 characters (XXXX-XXXX-XXXX)')
    .max(20, 'Verification code is too long')
    .regex(
      /^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/,
      'Use the format XXXX-XXXX-XXXX from your email',
    ),
})

type VerificationCodeFormData = z.infer<typeof verificationCodeSchema>

type Status = 'loading' | 'form' | 'success' | 'error'

export function EmailVerifiedPage() {
  const [searchParams] = useSearchParams()
  const urlToken = searchParams.get('token')
  const [status, setStatus] = useState<Status>(urlToken ? 'loading' : 'form')
  const [resending, setResending] = useState(false)
  const [resendSent, setResendSent] = useState(false)

  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<VerificationCodeFormData>({
    resolver: zodResolver(verificationCodeSchema),
    defaultValues: { verification_code: urlToken ?? '' },
  })

  useEffect(() => {
    if (!urlToken) return

    const verify = async () => {
      try {
        await api.post('/api/email/verify', { token: urlToken })
        setStatus('success')
      } catch {
        setStatus('form')
      }
    }

    verify()
  }, [urlToken])

  const onSubmit = async (data: VerificationCodeFormData) => {
    try {
      await api.post('/api/email/verify', { token: data.verification_code })
      setStatus('success')
    } catch (err) {
      const message =
        err instanceof ApiError
          ? typeof err.data === 'object' && err.data !== null && 'detail' in err.data
            ? String((err.data as { detail: unknown }).detail)
            : err.message
          : 'Verification failed. Please try again.'
      setError('verification_code', { type: 'server', message })
    }
  }

  const handleResend = async () => {
    setResending(true)
    try {
      await api.post('/api/email/resend-verification')
      setResendSent(true)
    } catch {
      // silently fail, user can retry
    } finally {
      setResending(false)
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-bg-primary p-8">
      <div className="w-full max-w-md space-y-6 text-center">
        <h1 className="text-2xl font-bold gradient-text">AuthGlow</h1>

        {status === 'loading' && (
          <div className="space-y-4">
            <Loader2 className="mx-auto h-8 w-8 animate-spin text-brand-violet" />
            <h2 className="text-xl font-semibold text-text-primary">Verifying your email...</h2>
          </div>
        )}

        {status === 'form' && (
          <div className="space-y-5 rounded-2xl border border-surface-2 bg-surface-1 p-8 text-left">
            <div className="space-y-2 text-center">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-brand-violet/10">
                <MailCheck className="h-7 w-7 text-brand-violet" />
              </div>
              <h2 className="text-xl font-semibold text-text-primary">Verify your email</h2>
              <p className="text-sm text-text-muted">
                Enter the verification code we sent to your email.
              </p>
            </div>

            <div className="rounded-xl border border-surface-2 bg-surface-1/50 p-3 text-xs text-text-muted">
              <div className="flex items-start gap-2">
                <KeyRound className="mt-0.5 h-4 w-4 shrink-0 text-brand-violet" />
                <p>
                  The code is in the email body (format{' '}
                  <span className="font-mono">XXXX-XXXX-XXXX</span>). It is never included in a
                  clickable link.
                </p>
              </div>
            </div>

            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
              <div className="space-y-2">
                <label
                  htmlFor="verification-code"
                  className="block text-sm font-medium text-text-secondary"
                >
                  Verification code
                </label>
                <input
                  id="verification-code"
                  type="text"
                  inputMode="text"
                  autoComplete="off"
                  autoCapitalize="characters"
                  spellCheck={false}
                  placeholder="XXXX-XXXX-XXXX"
                  aria-describedby="verification-code-help"
                  {...register('verification_code')}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-center font-mono text-base tracking-widest text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
                />
                <p id="verification-code-help" className="text-xs text-text-muted">
                  Copy the code exactly as shown, including the dashes.
                </p>
                {errors.verification_code && (
                  <FieldError id="verification-code-error">
                    {errors.verification_code.message}
                  </FieldError>
                )}
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                {isSubmitting ? 'Verifying...' : 'Verify email'}
              </button>
            </form>

            <div className="text-center text-xs text-text-muted">
              {resendSent ? (
                <p className="text-semantic-success">Verification email sent. Check your inbox.</p>
              ) : (
                <button
                  type="button"
                  onClick={handleResend}
                  disabled={resending}
                  className="inline-flex items-center gap-1.5 font-medium text-brand-violet hover:text-brand-blue transition-colors disabled:opacity-50"
                >
                  {resending ? <Loader2 size={12} className="animate-spin" /> : (
                    <RefreshCw size={12} />
                  )}
                  Resend verification email
                </button>
              )}
            </div>
          </div>
        )}

        {status === 'success' && (
          <div className="space-y-4 rounded-2xl border border-surface-2 bg-surface-1 p-8">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
              <MailCheck className="h-7 w-7 text-semantic-success" />
            </div>
            <h2 className="text-xl font-semibold text-text-primary">Email verified</h2>
            <p className="text-sm text-text-muted">
              Your email has been successfully verified. You can now sign in to your account.
            </p>
            <Link
              to={ROUTES.AUTH.LOGIN}
              className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
            >
              Sign in
            </Link>
          </div>
        )}

        {status === 'error' && (
          <div className="space-y-4 rounded-2xl border border-surface-2 bg-surface-1 p-8">
            <Banner variant="error">
              We could not verify your email with the link or code you provided.
            </Banner>
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-error/10">
              <AlertCircle className="h-7 w-7 text-semantic-error" />
            </div>
            <h2 className="text-xl font-semibold text-text-primary">Verification failed</h2>
            <p className="text-sm text-text-muted">
              This verification link is invalid or has expired. You can request a new one.
            </p>
            {resendSent ? (
              <p className="text-sm text-semantic-success">Verification email sent. Check your inbox.</p>
            ) : (
              <button
                onClick={handleResend}
                disabled={resending}
                className="inline-flex items-center gap-2 rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
              >
                {resending ? <Loader2 size={14} className="animate-spin" /> : <RefreshCw size={14} />}
                Resend verification email
              </button>
            )}
            <p className="text-xs text-text-muted">
              <Link
                to={ROUTES.AUTH.LOGIN}
                className="font-medium text-brand-violet hover:text-brand-blue transition-colors"
              >
                Back to sign in
              </Link>
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
