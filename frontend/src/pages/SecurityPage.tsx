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
    <div className="space-y-6">
      <PageHeader
        title="Security"
        description="Two-factor authentication, passkeys, and credentials."
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* COLUMN 1: MFA + Backup Codes */}
        <div className="space-y-6">
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-text-primary">Two-Factor Authentication</h2>
              <button
                onClick={() => { setShowMfaSetup(!showMfaSetup); fetchCurrentUser() }}
                className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-all ${
                  user?.mfa_enabled
                    ? 'border border-surface-2 text-text-secondary hover:bg-surface-2'
                    : 'bg-gradient-cta text-white shadow-glow-violet'
                }`}
              >
                {showMfaSetup ? 'Cancel' : user?.mfa_enabled ? 'Manage' : 'Enable'}
              </button>
            </div>
            <div className="flex items-center gap-3 rounded-xl bg-surface-2 p-4">
              <Shield size={20} className={user?.mfa_enabled ? 'text-semantic-success' : 'text-text-muted'} />
              <div className="flex-1">
                <p className="text-sm text-text-primary">MFA is {user?.mfa_enabled ? 'enabled' : 'not enabled'}</p>
                <p className="text-xs text-text-muted">
                  {user?.mfa_enabled ? 'Account protected with authenticator app codes.' : 'Add protection with Google Authenticator or similar app.'}
                </p>
              </div>
              <StatusBadge status={!!user?.mfa_enabled} trueLabel="On" falseLabel="Off" />
            </div>
            {showMfaSetup && <div className="mt-4 border-t border-surface-2 pt-4"><MFAEnrollment /></div>}
          </div>

          {backupCodes.length > 0 && (
            <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
              <h2 className="text-sm font-semibold text-text-primary mb-4">Backup Codes</h2>
              <BackupCodes codes={backupCodes} onRegenerate={handleCodesRegenerated} />
            </div>
          )}
        </div>

        {/* COLUMN 2: Passkeys + Trusted Devices */}
        <div className="space-y-6">
          <PasskeyManager />
          <TrustedDevices />
        </div>
      </div>

      {/* Credentials — full width, two columns */}
      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
        <h2 className="text-sm font-semibold text-text-primary mb-4">Credentials</h2>
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <ChangePasswordForm />
          <ChangeEmailForm />
        </div>
      </div>
    </div>
  )
}
