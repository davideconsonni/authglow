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
import { ConfirmDialog } from '@/components/shared/ConfirmDialog'
import { api } from '@/lib/api'
import { useAuth } from '@/hooks/useAuth'
import { useApiQuery } from '@/hooks/useApi'
import { useDocumentTitle } from '@/hooks/useDocumentTitle'

export function SecurityPage() {
  useDocumentTitle('Security')
  const { user, fetchCurrentUser } = useAuth()
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [showMfaSetup, setShowMfaSetup] = useState(false)
  const [disableMfa, setDisableMfa] = useState(false)
  const [error, setError] = useState('')

  const { data: mfaStatus } = useApiQuery<{ enabled: boolean; backup_codes_remaining?: number }>(['mfa-status'], '/api/mfa/status')

  const handleCodesRegenerated = async () => {
    try {
      const data = await api.post<{ backup_codes: string[] }>('/api/mfa/regenerate-backup-codes')
      setBackupCodes(data.backup_codes)
    } catch {}
  }

  const handleDisableMfa = async () => {
    setError('')
    try {
      await api.delete('/api/mfa/disable')
      setDisableMfa(false)
      await fetchCurrentUser()
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to disable MFA')
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Security" description="Two-factor authentication, passkeys, and credentials." />

      {error && <div className="rounded-xl bg-semantic-error/10 px-4 py-3 text-sm text-semantic-error" role="alert">{error}</div>}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <div className="space-y-6">
          {!user?.is_federated && (
            <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-text-primary">Two-Factor Authentication</h2>
                <div className="flex items-center gap-2">
                  {user?.mfa_enabled && (
                    <button
                      onClick={() => setDisableMfa(true)}
                      className="rounded-lg px-3 py-1.5 text-xs font-medium border border-semantic-error/30 text-semantic-error hover:bg-semantic-error/10 transition-colors"
                    >
                      Disable
                    </button>
                  )}
                  <button
                    onClick={() => { setShowMfaSetup(!showMfaSetup); fetchCurrentUser() }}
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition-all ${
                      user?.mfa_enabled && !disableMfa
                        ? 'border border-surface-2 text-text-secondary hover:bg-surface-2'
                        : 'bg-gradient-cta text-white shadow-glow-violet'
                    }`}
                  >
                    {showMfaSetup ? 'Cancel' : user?.mfa_enabled ? 'Manage' : 'Enable'}
                  </button>
                </div>
              </div>
              <div className="flex items-center gap-3 rounded-xl bg-surface-2 p-4">
                <Shield size={20} className={user?.mfa_enabled ? 'text-semantic-success' : 'text-text-muted'} />
                <div className="flex-1">
                  <p className="text-sm text-text-primary">MFA is {user?.mfa_enabled ? 'enabled' : 'not enabled'}</p>
                  <p className="text-xs text-text-muted">
                    {user?.mfa_enabled
                      ? `Account protected with authenticator app codes.${mfaStatus?.backup_codes_remaining !== undefined ? ` ${mfaStatus.backup_codes_remaining} backup codes remaining.` : ''}`
                      : 'Add protection with Google Authenticator or similar app.'}
                  </p>
                </div>
                <StatusBadge status={!!user?.mfa_enabled} trueLabel="On" falseLabel="Off" />
              </div>
              {showMfaSetup && <div className="mt-4 border-t border-surface-2 pt-4"><MFAEnrollment /></div>}
            </div>
          )}

          {backupCodes.length > 0 && (
            <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
              <h2 className="text-sm font-semibold text-text-primary mb-4">Backup Codes</h2>
              <BackupCodes codes={backupCodes} onRegenerate={handleCodesRegenerated} />
            </div>
          )}
        </div>

        <div className="space-y-6">
          {!user?.is_federated && <PasskeyManager />}
          <TrustedDevices />
        </div>
      </div>

      <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
        <h2 className="text-sm font-semibold text-text-primary mb-4">Credentials</h2>
        {user?.is_federated && (
          <p className="text-xs text-text-muted mb-4">
            Password, MFA, and passkeys are managed by your identity provider (Zitadel/Google/CIE).
          </p>
        )}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {!user?.is_federated && <ChangePasswordForm />}
          {!user?.is_federated && <ChangeEmailForm />}
        </div>
      </div>

      <ConfirmDialog
        open={disableMfa}
        title="Disable Two-Factor Authentication"
        message="Are you sure? Your account will be less secure without MFA. You can re-enable it at any time."
        confirmLabel="Disable MFA"
        variant="danger"
        onConfirm={handleDisableMfa}
        onCancel={() => setDisableMfa(false)}
      />
    </div>
  )
}
