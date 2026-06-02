import { useState } from 'react'
import { Shield } from 'lucide-react'
import { PageHeader } from '@/components/layout/PageHeader'
import { MFAEnrollment } from '@/components/profile/MFAEnrollment'
import { BackupCodes } from '@/components/profile/BackupCodes'
import { TrustedDevices } from '@/components/profile/TrustedDevices'
import { PasskeyManager } from '@/components/profile/PasskeyManager'
import { ChangePasswordForm } from '@/components/profile/ChangePasswordForm'
import { ChangeEmailForm } from '@/components/profile/ChangeEmailForm'
import { StatusBadge } from '@/components/shared/StatusBadge'
import { Section } from '@/components/shared/Section'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'

export function SecurityPage() {
  const { user, fetchCurrentUser } = useAuth()
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [showMfaSetup, setShowMfaSetup] = useState(false)

  const handleCodesRegenerated = async () => {
    try {
      const data = await api.post<{ backup_codes: string[] }>('/api/mfa/regenerate-backup-codes')
      setBackupCodes(data.backup_codes)
    } catch {}
  }

  return (
    <div className="space-y-10">
      <PageHeader
        title="Security"
        description="Manage authentication, MFA, passkeys, and credentials for your account."
      />

      {/* MFA Status */}
      <Section
        title="Two-Factor Authentication (MFA)"
        description="Add an extra layer of security by requiring a code from your authenticator app."
        actions={
          <button
            onClick={() => { setShowMfaSetup(!showMfaSetup); fetchCurrentUser() }}
            className={`rounded-xl px-4 py-2 text-sm font-semibold transition-all ${
              user?.mfa_enabled
                ? 'border border-surface-2 text-text-secondary hover:bg-surface-2'
                : 'bg-gradient-cta text-white shadow-glow-violet hover:scale-[1.02] active:scale-[0.98]'
            }`}
          >
            {user?.mfa_enabled ? (showMfaSetup ? 'Hide' : 'Manage MFA') : (showMfaSetup ? 'Cancel' : 'Enable MFA')}
          </button>
        }
      >
        <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
          <div className="flex items-center gap-4 mb-4">
            <div className={`flex h-12 w-12 items-center justify-center rounded-2xl ${
              user?.mfa_enabled ? 'bg-semantic-success/10' : 'bg-surface-2'
            }`}>
              <Shield size={24} className={user?.mfa_enabled ? 'text-semantic-success' : 'text-text-muted'} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-text-primary">
                MFA is {user?.mfa_enabled ? 'enabled' : 'not enabled'}
              </h3>
              <p className="text-xs text-text-muted mt-0.5">
                {user?.mfa_enabled
                  ? 'Your account is protected with two-factor authentication.'
                  : 'Enable MFA to protect your account from unauthorized access.'}
              </p>
            </div>
            <StatusBadge
              status={!!user?.mfa_enabled}
              trueLabel="Protected"
              falseLabel="Not protected"
              trueClass="bg-semantic-success/10 text-semantic-success"
              falseClass="bg-semantic-warning/10 text-semantic-warning"
            />
          </div>

          {showMfaSetup && (
            <div className="border-t border-surface-2 pt-6">
              <MFAEnrollment />
            </div>
          )}
        </div>
      </Section>

      {/* Backup Codes (only when MFA active + codes available) */}
      {backupCodes.length > 0 && (
        <Section title="Backup Codes" description="One-time recovery codes. Store them safely.">
          <BackupCodes codes={backupCodes} onRegenerate={handleCodesRegenerated} />
        </Section>
      )}

      {/* Passkeys */}
      <Section title="Passkeys" description="Passwordless authentication with biometrics or security keys.">
        <PasskeyManager />
      </Section>

      {/* Trusted Devices */}
      <Section title="Trusted Devices" description="Devices that can skip MFA after successful verification.">
        <TrustedDevices />
      </Section>

      {/* Credentials */}
      <Section title="Credentials" description="Update your password and email address.">
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <ChangePasswordForm />
          <ChangeEmailForm />
        </div>
      </Section>
    </div>
  )
}
