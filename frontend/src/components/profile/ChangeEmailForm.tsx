import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Loader2, Mail } from 'lucide-react'
import { api } from '@/lib/api'

const schema = z.object({
  new_email: z.string().email('Invalid email'),
  password: z.string().min(1, 'Password is required'),
})

type FormData = z.infer<typeof schema>

export function ChangeEmailForm() {
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({ resolver: zodResolver(schema) })

  const onSubmit = async (data: FormData) => {
    setError('')
    setSuccess(false)
    try {
      await api.post('/api/profile/me/change-email', data)
      setSuccess(true)
      reset()
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Email change failed')
    }
  }

  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Mail size={20} className="text-brand-blue" />
        <h3 className="text-sm font-semibold text-text-primary">Change Email</h3>
      </div>
      {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">Verification email sent to new address</div>}
      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-3">
        <input {...register('new_email')} placeholder="New email address" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20" />
        {errors.new_email && <p className="text-xs text-semantic-error">{errors.new_email.message}</p>}
        <input type="password" {...register('password')} placeholder="Confirm with password" className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20" />
        {errors.password && <p className="text-xs text-semantic-error">{errors.password.message}</p>}
        <button type="submit" disabled={isSubmitting} className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50">
          {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : null}
          Change email
        </button>
      </form>
    </div>
  )
}
