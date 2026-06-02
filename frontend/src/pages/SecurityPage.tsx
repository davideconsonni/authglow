import { useState } from 'react'
import { PageHeader } from '@/components/layout/PageHeader'
import { MFAEnrollment } from '@/components/profile/MFAEnrollment'
import { BackupCodes } from '@/components/profile/BackupCodes'
import { TrustedDevices } from '@/components/profile/TrustedDevices'
import { api } from '@/lib/api'

export function SecurityPage() {
  const [backupCodes, setBackupCodes] = useState<string[]>([])

  const handleCodesRegenerated = async () => {
    try {
      const data = await api.post<{ backup_codes: string[] }>(
        '/api/mfa/regenerate-backup-codes',
      )
      setBackupCodes(data.backup_codes)
    } catch {
      // ignore
    }
  }

  return (
    <div>
      <PageHeader
        title="Security"
        description="Manage your account security, MFA, and trusted devices."
      />

      <div className="space-y-8">
        {/* MFA Section */}
        <section>
          <h2 className="mb-4 text-lg font-semibold text-text-primary">
            Two-Factor Authentication
          </h2>
          <div className="rounded-2xl border border-surface-2 bg-surface-1 p-6">
            <MFAEnrollment />
          </div>
        </section>

        {/* Backup Codes */}
        {backupCodes.length > 0 && (
          <section>
            <h2 className="mb-4 text-lg font-semibold text-text-primary">Backup Codes</h2>
            <BackupCodes codes={backupCodes} onRegenerate={handleCodesRegenerated} />
          </section>
        )}

        {/* Trusted Devices */}
        <section>
          <h2 className="mb-4 text-lg font-semibold text-text-primary">Trusted Devices</h2>
          <TrustedDevices />
        </section>
      </div>
    </div>
  )
}
