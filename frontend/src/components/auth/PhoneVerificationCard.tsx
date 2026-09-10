import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Smartphone, Loader2 } from 'lucide-react'
import { api } from '../../lib/api'

const phoneSchema = z.object({
  phone: z
    .string()
    .trim()
    .regex(/^\+[1-9]\d{7,14}$/, 'Use international format, e.g. +393391223345'),
})

const codeSchema = z.object({
  code: z
    .string()
    .trim()
    .regex(/^\d{6}$/, 'The code is 6 digits'),
})

type PhoneForm = z.infer<typeof phoneSchema>
type CodeForm = z.infer<typeof codeSchema>

interface PhoneVerificationCardProps {
  phone: string | null
  phoneVerified: boolean
  onVerified: () => void
}

export function PhoneVerificationCard({ phone, phoneVerified, onVerified }: PhoneVerificationCardProps) {
  const [editing, setEditing] = useState(!phoneVerified)
  const [codeSent, setCodeSent] = useState(false)
  const [verified, setVerified] = useState(false)
  const [requestError, setRequestError] = useState<string | null>(null)
  const [verifyError, setVerifyError] = useState<string | null>(null)

  const phoneForm = useForm<PhoneForm>({
    resolver: zodResolver(phoneSchema),
    values: { phone: phone ?? '' },
  })
  const codeForm = useForm<CodeForm>({
    resolver: zodResolver(codeSchema),
    defaultValues: { code: '' },
  })

  const handleSend = async (data: PhoneForm) => {
    setRequestError(null)
    try {
      await api.post('/api/phone/request', { phone: data.phone })
      setCodeSent(true)
    } catch (err: unknown) {
      setRequestError(err instanceof Error ? err.message : 'Failed to send code')
    }
  }

  const handleVerify = async (data: CodeForm) => {
    setVerifyError(null)
    const currentPhone = phoneForm.getValues('phone')
    try {
      await api.post('/api/phone/verify', { phone: currentPhone, code: data.code })
      setVerified(true)
      setEditing(false)
      onVerified()
    } catch (err: unknown) {
      setVerifyError(err instanceof Error ? err.message : 'Verification failed')
    }
  }

  if ((phoneVerified || verified) && !editing) {
    return (
      <div className="rounded-xl bg-semantic-success/10 px-4 py-3" data-testid="phone-verified">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-xs text-semantic-success">
            <Smartphone size={14} className="shrink-0" />
            <span>{phone} verified.</span>
          </div>
          <button
            onClick={() => {
              setEditing(true)
              setCodeSent(false)
              setVerified(false)
            }}
            className="rounded-lg bg-semantic-success/20 px-3 py-1 text-xs font-medium text-semantic-success hover:bg-semantic-success/30 transition-colors shrink-0"
          >
            Change
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="rounded-xl bg-semantic-info/10 border border-semantic-info/20 px-4 py-3 space-y-3" data-testid="phone-verification-card">
      <div className="flex items-center gap-2 text-xs text-text-secondary">
        <Smartphone size={14} className="text-semantic-info shrink-0" />
        <span>Verify your phone number to enable all features.</span>
      </div>

      {!codeSent ? (
        <form onSubmit={phoneForm.handleSubmit(handleSend)} className="space-y-2">
          {requestError && (
            <p role="alert" className="text-xs text-semantic-error">
              {requestError}
            </p>
          )}
          <div className="flex gap-2">
            <div className="flex-1">
              <input
                {...phoneForm.register('phone')}
                placeholder="+393391223345"
                inputMode="tel"
                data-testid="phone-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
              />
              {phoneForm.formState.errors.phone && (
                <p role="alert" className="mt-1 text-xs text-semantic-error">
                  {phoneForm.formState.errors.phone.message}
                </p>
              )}
            </div>
            <button
              type="submit"
              disabled={phoneForm.formState.isSubmitting}
              data-testid="send-code-button"
              className="rounded-xl bg-semantic-info/20 px-4 py-2 text-xs font-medium text-semantic-info hover:bg-semantic-info/30 transition-colors disabled:opacity-50 shrink-0"
            >
              {phoneForm.formState.isSubmitting ? <Loader2 size={12} className="animate-spin" /> : 'Send code'}
            </button>
          </div>
        </form>
      ) : (
        <form onSubmit={codeForm.handleSubmit(handleVerify)} className="space-y-2">
          {verifyError && (
            <p role="alert" className="text-xs text-semantic-error">
              {verifyError}
            </p>
          )}
          <div className="flex gap-2">
            <div className="flex-1">
              <input
                {...codeForm.register('code')}
                placeholder="123456"
                inputMode="numeric"
                maxLength={6}
                data-testid="code-input"
                className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-2 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-accent focus:outline-none focus:ring-2 focus:ring-brand-accent/20"
              />
              {codeForm.formState.errors.code && (
                <p role="alert" className="mt-1 text-xs text-semantic-error">
                  {codeForm.formState.errors.code.message}
                </p>
              )}
            </div>
            <button
              type="submit"
              disabled={codeForm.formState.isSubmitting}
              data-testid="verify-code-button"
              className="rounded-xl bg-semantic-info/20 px-4 py-2 text-xs font-medium text-semantic-info hover:bg-semantic-info/30 transition-colors disabled:opacity-50 shrink-0"
            >
              {codeForm.formState.isSubmitting ? <Loader2 size={12} className="animate-spin" /> : 'Verify'}
            </button>
          </div>
          <button
            type="button"
            onClick={() => {
              setCodeSent(false)
              setVerifyError(null)
            }}
            className="text-xs text-text-muted hover:text-text-secondary transition-colors"
          >
            Use a different number
          </button>
        </form>
      )}
    </div>
  )
}
