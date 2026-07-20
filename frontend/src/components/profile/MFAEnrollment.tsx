import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import {
  Loader2,
  QrCode,
  Download,
  Copy,
  Check,
  KeyRound,
  Shield,
  RefreshCw,
} from 'lucide-react'
import { api } from '../../lib/api'

const verifySchema = z.object({
  code: z.string().length(6, 'Enter the 6-digit code from your app'),
})

type VerifyFormData = z.infer<typeof verifySchema>

interface EnrollmentData {
  qr_code: string
  secret: string
  backup_codes: string[]
}

interface Props {
  isEnabled?: boolean
  onRefreshUser?: () => Promise<void>
}

export function MFAEnrollment({ isEnabled = false, onRefreshUser }: Props) {
  const [step, setStep] = useState<'enroll' | 'loading' | 'verify' | 'manage'>('enroll')
  const [enrollmentData, setEnrollmentData] = useState<EnrollmentData | null>(null)
  const [error, setError] = useState('')
  const [copiedField, setCopiedField] = useState<string | null>(null)
  const navigate = useNavigate()

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<VerifyFormData>({
    resolver: zodResolver(verifySchema),
  })

  useEffect(() => {
    if (isEnabled) setStep('manage')
  }, [isEnabled])

  const startEnrollment = async () => {
    setError('')
    setStep('loading')
    try {
      const data = await api.post<EnrollmentData>('/api/mfa/enroll')
      setEnrollmentData(data)
      setStep('verify')
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Failed to start MFA enrollment.')
      setStep('enroll')
    }
  }

  const handleCopy = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const handleDownloadBackupCodes = () => {
    if (!enrollmentData) return
    const content = enrollmentData.backup_codes.join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'authglow-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  const onVerify = async (data: VerifyFormData) => {
    setError('')
    try {
      await api.post('/api/mfa/verify', {
        code: data.code,
      })
      await onRefreshUser?.()
      navigate('/security')
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : ''
      setError(message || 'Verification failed. Please try again.')
    }
  }

  if (step === 'loading') {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-6 w-6 animate-spin text-brand-violet" />
      </div>
    )
  }

  if (step === 'manage') {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-semantic-success/10">
          <Shield className="h-7 w-7 text-semantic-success" />
        </div>
        <h3 className="text-lg font-semibold text-text-primary">Two-factor authentication is active</h3>
        <p className="text-sm text-text-muted">
          Your account is protected with authenticator app codes.
        </p>
        {error && (
          <p className="text-sm text-semantic-error" role="alert">{error}</p>
        )}
        <button
          onClick={async () => {
            setError('')
            setStep('loading')
            try {
              const data = await api.post<EnrollmentData>('/api/mfa/enroll')
              setEnrollmentData(data)
              setStep('verify')
            } catch (err: unknown) {
              const message = err instanceof Error ? err.message : ''
              setError(message || 'Failed to regenerate.')
              setStep('manage')
            }
          }}
          className="inline-flex items-center justify-center gap-2 rounded-xl border border-surface-2 bg-surface-1 px-6 py-2.5 text-sm font-medium text-text-primary hover:bg-surface-2 transition-colors"
        >
          <RefreshCw className="h-4 w-4" />
          Regenerate Backup Codes
        </button>
      </div>
    )
  }

  if (step === 'enroll' || !enrollmentData) {
    return (
      <div className="space-y-4 text-center">
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-2">
          <KeyRound className="h-7 w-7 text-text-muted" />
        </div>
        <h3 className="text-lg font-semibold text-text-primary">Set up two-factor authentication</h3>
        <p className="text-sm text-text-muted">
          Add an extra layer of security to your account by enabling TOTP-based authentication.
        </p>
        {error && (
          <p className="text-sm text-semantic-error" role="alert">{error}</p>
        )}
        <button
          onClick={startEnrollment}
          className="inline-flex items-center justify-center rounded-xl bg-gradient-cta px-6 py-2.5 text-sm font-semibold text-white shadow-glow-violet transition-all hover:scale-[1.02] active:scale-[0.98]"
        >
          Enable MFA
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-brand-violet/10">
            <QrCode className="h-5 w-5 text-brand-violet" />
          </div>
          <div>
            <h3 className="font-semibold text-text-primary">Scan QR Code</h3>
            <p className="text-xs text-text-muted">Use Google Authenticator or similar app</p>
          </div>
        </div>

        <div className="mt-4 flex justify-center rounded-2xl bg-white p-4">
          <img
            src={enrollmentData.qr_code}
            alt="MFA QR Code"
            className="h-48 w-48"
          />
        </div>

        <div className="mt-4 flex items-center justify-between rounded-xl bg-surface-2 px-4 py-2">
          <code className="text-sm text-text-secondary">{enrollmentData.secret}</code>
          <button
            onClick={() => handleCopy(enrollmentData.secret, 'secret')}
            className="text-text-muted hover:text-text-secondary transition-colors"
            aria-label="Copy secret"
          >
            {copiedField === 'secret' ? <Check size={16} className="text-semantic-success" /> : <Copy size={16} />}
          </button>
        </div>
      </div>

      {/* Backup codes */}
      <div className="rounded-2xl border border-surface-2 p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-sm font-semibold text-text-primary">Backup Codes</h4>
          <div className="flex gap-2">
            <button
              onClick={() => handleCopy(enrollmentData.backup_codes.join('\n'), 'codes')}
              className="flex items-center gap-1 rounded-lg bg-surface-2 px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
            >
              {copiedField === 'codes' ? <Check size={12} /> : <Copy size={12} />}
              {copiedField === 'codes' ? 'Copied' : 'Copy'}
            </button>
            <button
              onClick={handleDownloadBackupCodes}
              className="flex items-center gap-1 rounded-lg bg-surface-2 px-2.5 py-1 text-xs text-text-secondary hover:text-text-primary transition-colors"
            >
              <Download size={12} />
              Download
            </button>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {enrollmentData.backup_codes.map((code, i) => (
            <code
              key={i}
              className="rounded-lg bg-surface-2 px-3 py-1.5 text-center text-xs font-mono text-text-secondary"
            >
              {code}
            </code>
          ))}
        </div>
        <p className="text-xs text-semantic-warning">
          Store these codes securely. They cannot be recovered.
        </p>
      </div>

      {/* Verification */}
      <div className="space-y-4">
        <p className="text-sm text-text-secondary">
          Enter a 6-digit code from your authenticator app to verify setup:
        </p>
        <form onSubmit={handleSubmit(onVerify)} className="space-y-4">
          <input
            type="text"
            inputMode="numeric"
            maxLength={6}
            placeholder="000000"
            {...register('code')}
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-center text-lg font-semibold tracking-widest text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
          />
          {errors.code && (
            <p className="text-xs text-semantic-error" role="alert">{errors.code.message}</p>
          )}
          {error && (
            <p className="text-sm text-semantic-error" role="alert">{error}</p>
          )}
          <button
            type="submit"
            disabled={isSubmitting}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isSubmitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Verify & Enable
          </button>
        </form>
      </div>
    </div>
  )
}
