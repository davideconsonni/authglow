import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { useNavigate } from 'react-router-dom'
import { Loader2, Eye, EyeOff, Lock } from 'lucide-react'
import { api } from '../../lib/api'
import { ROUTES } from '../../lib/constants'
import { useAuth } from '../../hooks/useAuth'

const changePasswordSchema = z
  .object({
    current_password: z.string().min(1, 'Current password is required'),
    new_password: z
      .string()
      .min(12, 'Must be at least 12 characters')
      .regex(/[A-Z]/, 'Must contain an uppercase letter')
      .regex(/[a-z]/, 'Must contain a lowercase letter')
      .regex(/[0-9]/, 'Must contain a digit')
      .regex(/[^A-Za-z0-9]/, 'Must contain a special character'),
    confirm_password: z.string(),
  })
  .refine((d) => d.new_password === d.confirm_password, {
    message: 'Passwords do not match',
    path: ['confirm_password'],
  })

type FormData = z.infer<typeof changePasswordSchema>

export function ChangePasswordForm() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [showCurrent, setShowCurrent] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [success, setSuccess] = useState(false)
  const [error, setError] = useState('')

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<FormData>({ resolver: zodResolver(changePasswordSchema) })

  const onSubmit = async (data: FormData) => {
    setError('')
    setSuccess(false)
    try {
      await api.post('/api/profile/me/change-password', {
        current_password: data.current_password,
        new_password: data.new_password,
      })
      setSuccess(true)
      reset()
      // The backend revokes every session on password change (including
      // this browser's cookies) — bounce to login after a short beat so
      // the success message is actually readable.
      setTimeout(() => navigate(ROUTES.AUTH.LOGIN, { replace: true }), 1500)
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Password change failed')
    }
  }

  return (
    <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6 space-y-4">
      <div className="flex items-center gap-3">
        <Lock size={20} className="text-brand-accent" />
        <h3 className="text-sm font-semibold text-text-primary">Change Password</h3>
      </div>

      {success && <div className="rounded-xl bg-semantic-success/10 px-4 py-2 text-xs text-semantic-success">Password changed. All sessions were revoked — redirecting you to sign in again...</div>}
      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-2 text-xs text-semantic-error">{error}</div>}

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-3">
        <input type="hidden" autoComplete="username" value={user?.email ?? ''} />
        {(['current_password', 'new_password'] as const).map((field, i) => {
          const show = i === 0 ? showCurrent : showNew
          const setShow = i === 0 ? setShowCurrent : setShowNew
          const label = i === 0 ? 'Current password' : 'New password'
          const placeholder = i === 0 ? 'Enter current password' : 'Enter new password'

          return (
            <div key={field}>
              <label className="block text-xs text-text-secondary mb-1">{label}</label>
              <div className="relative">
                <input
                  type={show ? 'text' : 'password'}
                  autoComplete={field === 'current_password' ? 'current-password' : 'new-password'}
                  {...register(field)}
                  placeholder={placeholder}
                  className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 pr-10 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
                />
                <button type="button" onClick={() => setShow(!show)} className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted" aria-label="Toggle visibility">
                  {show ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>
          )
        })}
        <div>
          <label className="block text-xs text-text-secondary mb-1">Confirm new password</label>
          <input
            type="password"
            autoComplete="new-password"
            {...register('confirm_password')}
            placeholder="Confirm new password"
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2.5 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
          />
          {errors.confirm_password && <p className="mt-1 text-xs text-semantic-error">{errors.confirm_password.message}</p>}
        </div>
        <button
          type="submit"
          disabled={isSubmitting}
          className="flex items-center gap-2 rounded-xl bg-gradient-cta px-4 py-2 text-sm font-semibold text-white shadow-glow-accent transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
        >
          {isSubmitting ? <Loader2 size={16} className="animate-spin" /> : null}
          Update password
        </button>
      </form>
    </div>
  )
}
