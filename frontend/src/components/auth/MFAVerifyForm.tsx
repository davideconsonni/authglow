import { useState, useRef, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Loader2, Timer } from 'lucide-react'
import { api } from '@/lib/api'
import { useAuthStore } from '@/stores/authStore'
import { useNavigate } from 'react-router-dom'
import { ROUTES } from '@/lib/constants'

export function MFAVerifyForm() {
  const [searchParams] = useSearchParams()
  const sessionToken = searchParams.get('session_token')
  const [digits, setDigits] = useState<string[]>(Array(6).fill(''))
  const [isBackupCode, setIsBackupCode] = useState(false)
  const [backupInput, setBackupInput] = useState('')
  const [lockoutUntil, setLockoutUntil] = useState<number | null>(null)
  const [remainingSeconds, setRemainingSeconds] = useState(0)
  const [attemptsLeft, setAttemptsLeft] = useState(3)
  const [generalError, setGeneralError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const setAuthenticated = useAuthStore((s) => s.setAuthenticated)
  const fetchCurrentUser = useAuthStore((s) => s.fetchCurrentUser)
  const navigate = useNavigate()
  const inputRefs = useRef<(HTMLInputElement | null)[]>([])

  const handleVerify = useCallback(
    async (code: string) => {
      setGeneralError('')
      setSubmitting(true)
      try {
        const response = await api.post<{
          access_token: string
          refresh_token?: string
          redirect_url?: string
          mfa_required?: boolean
        }>('/api/mfa/verify-login', {
          session_token: sessionToken,
          code,
        })

        if (response.redirect_url) {
          window.location.href = response.redirect_url
          return
        }

        if (response.access_token) {
          setAuthenticated(true)
          await fetchCurrentUser()
          navigate(ROUTES.DASHBOARD)
          return
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : ''
        const status = (err as { status?: number }).status

        if (status === 429 || message.includes('lockout')) {
          const newAttempts = attemptsLeft - 1
          setAttemptsLeft(newAttempts)
          if (newAttempts <= 0) {
            const lockoutTime = Date.now() + 30000
            setLockoutUntil(lockoutTime)
            setRemainingSeconds(30)
          }
          setGeneralError(
            newAttempts <= 0
              ? 'Too many failed attempts. Please wait 30 seconds.'
              : `Invalid code. ${newAttempts} attempt${newAttempts === 1 ? '' : 's'} remaining.`,
          )
        } else {
          setGeneralError('Invalid code. Please try again.')
        }
      } finally {
        setSubmitting(false)
      }
    },
    [sessionToken, attemptsLeft],
  )

  useEffect(() => {
    if (!lockoutUntil) return
    setRemainingSeconds(Math.ceil((lockoutUntil - Date.now()) / 1000))
    const interval = setInterval(() => {
      const remaining = Math.ceil((lockoutUntil - Date.now()) / 1000)
      if (remaining <= 0) {
        setLockoutUntil(null)
        setAttemptsLeft(3)
        clearInterval(interval)
      } else {
        setRemainingSeconds(remaining)
      }
    }, 1000)
    return () => clearInterval(interval)
  }, [lockoutUntil])

  useEffect(() => {
    if (digits.every((d) => d !== '')) {
      handleVerify(digits.join(''))
    }
  }, [digits, handleVerify])

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputRefs.current[index - 1]?.focus()
    }
  }

  const handleDigitChange = (index: number, value: string) => {
    if (!/^\d*$/.test(value)) return
    const newDigits = [...digits]
    newDigits[index] = value.slice(-1)
    setDigits(newDigits)

    if (value && index < 5) {
      inputRefs.current[index + 1]?.focus()
    }
  }

  const handleBackupSubmit = () => {
    if (backupInput.length >= 8) {
      handleVerify(backupInput)
    }
  }

  const isLocked = lockoutUntil !== null

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        if (isBackupCode) {
          handleBackupSubmit()
        }
      }}
      className="space-y-6"
    >
      {generalError && (
        <div className="rounded-xl border border-semantic-error/30 bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">
          {generalError}
        </div>
      )}

      {isLocked && (
        <div className="flex items-center gap-2 rounded-xl border border-semantic-warning/30 bg-semantic-warning/10 px-4 py-3 text-sm text-semantic-warning">
          <Timer size={18} />
          <span>Locked. Try again in {remainingSeconds}s</span>
        </div>
      )}

      {!isBackupCode ? (
        <>
          <p className="text-center text-sm text-text-secondary">
            Enter the 6-digit code from your authenticator app
          </p>
          <div className="flex justify-center gap-3">
            {digits.map((digit, index) => (
              <input
                key={index}
                ref={(el) => {
                  inputRefs.current[index] = el
                }}
                type="text"
                inputMode="numeric"
                maxLength={1}
                value={digit}
                disabled={isLocked || submitting}
                onChange={(e) => handleDigitChange(index, e.target.value)}
                onKeyDown={(e) => handleKeyDown(index, e)}
                onFocus={(e) => e.target.select()}
                className="h-14 w-12 rounded-xl border border-surface-2 bg-surface-1 text-center text-xl font-semibold text-text-primary focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors disabled:opacity-50"
              />
            ))}
          </div>
          <button
            type="button"
            onClick={() => setIsBackupCode(true)}
            className="block w-full text-center text-sm text-brand-violet hover:text-brand-blue transition-colors"
          >
            Use a backup code instead
          </button>
        </>
      ) : (
        <>
          <p className="text-center text-sm text-text-secondary">
            Enter a backup recovery code
          </p>
          <input
            type="text"
            value={backupInput}
            onChange={(e) => setBackupInput(e.target.value)}
            placeholder="Enter 8+ character backup code"
            disabled={isLocked || submitting}
            className="w-full rounded-xl border border-surface-2 bg-surface-1 px-4 py-3 text-sm text-text-primary placeholder:text-text-muted focus:border-brand-violet focus:outline-none focus:ring-2 focus:ring-brand-violet/20 transition-colors"
          />
          <button
            type="button"
            onClick={() => setIsBackupCode(false)}
            className="block w-full text-center text-sm text-brand-violet hover:text-brand-blue transition-colors"
          >
            Use authenticator app instead
          </button>
          <button
            type="submit"
            disabled={isLocked || submitting || backupInput.length < 8}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-cta px-4 py-3 text-sm font-semibold text-white shadow-glow-violet transition-all duration-150 hover:scale-[1.02] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Verify backup code
          </button>
        </>
      )}
    </form>
  )
}
