import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2 } from 'lucide-react'
import { api } from '@/lib/api'
import { ROUTES } from '@/lib/constants'

const setupSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z
    .string()
    .min(12, 'Must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain an uppercase letter')
    .regex(/[a-z]/, 'Must contain a lowercase letter')
    .regex(/[0-9]/, 'Must contain a digit')
    .regex(/[^A-Za-z0-9]/, 'Must contain a special character'),
})

type SetupFormData = z.infer<typeof setupSchema>

export function SetupWizard() {
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<SetupFormData>({
    resolver: zodResolver(setupSchema),
  })

  const onSubmit = async (data: SetupFormData) => {
    setError('')
    try {
      await api.post('/api/setup/create-admin', {
        email: data.email,
        password: data.password,
        first_name: 'Admin',
        last_name: 'User',
      })
      setSuccess(true)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Setup failed. Please try again.')
    }
  }

  if (success) {
    return (
      <div className="space-y-6 text-center">
        <h3 className="text-xl font-semibold text-text-primary">Setup complete!</h3>
        <p className="text-sm text-text-muted">
          Your administrator account has been created. You can now sign in.
        </p>
        <a
          href={ROUTES.AUTH.LOGIN}
          className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          Go to login
        </a>
      </div>
    )
  }

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-5">
      {error && (
        <div className="rounded-xl border border-semantic-error/30 bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">
          {error}
        </div>
      )}

      <div className="space-y-2">
        <label htmlFor="setup-email" className="block text-sm font-medium text-text-secondary">
          Admin email
        </label>
        <input
          id="setup-email"
          type="email"
          autoComplete="email"
          placeholder="admin@example.com"
          {...register('email')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.email && <p className="text-xs text-semantic-error" role="alert">{errors.email.message}</p>}
      </div>

      <div className="space-y-2">
        <label htmlFor="setup-password" className="block text-sm font-medium text-text-secondary">
          Admin password
        </label>
        <input
          id="setup-password"
          type="password"
          autoComplete="new-password"
          placeholder="Create a strong password"
          {...register('password')}
          className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
        />
        {errors.password && <p className="text-xs text-semantic-error" role="alert">{errors.password.message}</p>}
      </div>

      <button
        type="submit"
        disabled={isSubmitting}
        className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
        Create admin account
      </button>
    </form>
  )
}
