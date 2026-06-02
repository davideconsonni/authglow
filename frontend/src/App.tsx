import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'
import { ROUTES } from '@/lib/constants'
import { useAuth } from '@/hooks/useAuth'
import { LoginPage } from '@/pages/auth/LoginPage'
import { RegisterPage } from '@/pages/auth/RegisterPage'
import { ForgotPasswordPage } from '@/pages/auth/ForgotPasswordPage'
import { ResetPasswordPage } from '@/pages/auth/ResetPasswordPage'
import { EmailVerifiedPage } from '@/pages/auth/EmailVerifiedPage'
import { OAuthConsentPage } from '@/pages/OAuthConsentPage'
import { MFAVerifyPage } from '@/pages/auth/MFAVerifyPage'
import { SecurityPage } from '@/pages/SecurityPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { ProfilePage } from '@/pages/ProfilePage'
import { SessionsPage } from '@/pages/SessionsPage'
import { ApiKeysPage } from '@/pages/ApiKeysPage'
import { SetupPage } from '@/pages/SetupPage'
import { AdminDashboardPage } from '@/pages/admin/AdminDashboardPage'
import { AdminUsersPage } from '@/pages/admin/AdminUsersPage'
import { AdminOAuthClientsPage } from '@/pages/admin/AdminOAuthClientsPage'
import { AdminSessionsPage } from '@/pages/admin/AdminSessionsPage'
import { AdminConsentsPage } from '@/pages/admin/AdminConsentsPage'
import { AdminApiKeysPage } from '@/pages/admin/AdminApiKeysPage'
import { AdminRbacPage } from '@/pages/admin/AdminRbacPage'
import { AdminJwkKeysPage } from '@/pages/admin/AdminJwkKeysPage'
import { AdminPasswordResetsPage } from '@/pages/admin/AdminPasswordResetsPage'
import { AdminPlaygroundPage } from '@/pages/admin/AdminPlaygroundPage'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 1000 * 60 * 5, retry: 1 },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) return <Navigate to={ROUTES.AUTH.LOGIN} replace />
  return <>{children}</>
}

function GuestRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (isAuthenticated) return <Navigate to={ROUTES.DASHBOARD} replace />
  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path={ROUTES.AUTH.LOGIN} element={<GuestRoute><LoginPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.REGISTER} element={<GuestRoute><RegisterPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.FORGOT_PASSWORD} element={<GuestRoute><ForgotPasswordPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.RESET_PASSWORD} element={<GuestRoute><ResetPasswordPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.MFA_VERIFY} element={<MFAVerifyPage />} />
          <Route path={ROUTES.AUTH.VERIFY_EMAIL} element={<EmailVerifiedPage />} />
          <Route path={ROUTES.OAUTH_CONSENT} element={<OAuthConsentPage />} />
          <Route path={ROUTES.SETUP} element={<SetupPage />} />

          <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
            <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
            <Route path={ROUTES.PROFILE} element={<ProfilePage />} />
            <Route path={ROUTES.SECURITY} element={<SecurityPage />} />
            <Route path={ROUTES.SESSIONS} element={<SessionsPage />} />
            <Route path={ROUTES.API_KEYS} element={<ApiKeysPage />} />
            <Route path={ROUTES.ADMIN.DASHBOARD} element={<AdminDashboardPage />} />
            <Route path={ROUTES.ADMIN.USERS} element={<AdminUsersPage />} />
            <Route path={ROUTES.ADMIN.OAUTH_CLIENTS} element={<AdminOAuthClientsPage />} />
            <Route path={ROUTES.ADMIN.SESSIONS} element={<AdminSessionsPage />} />
            <Route path={ROUTES.ADMIN.CONSENTS} element={<AdminConsentsPage />} />
            <Route path={ROUTES.ADMIN.API_KEYS} element={<AdminApiKeysPage />} />
            <Route path={ROUTES.ADMIN.RBAC} element={<AdminRbacPage />} />
            <Route path={ROUTES.ADMIN.JWK_KEYS} element={<AdminJwkKeysPage />} />
            <Route path={ROUTES.ADMIN.PASSWORD_RESETS} element={<AdminPasswordResetsPage />} />
            <Route path={ROUTES.ADMIN.PLAYGROUND} element={<AdminPlaygroundPage />} />
          </Route>

          <Route path="/" element={<Navigate to={ROUTES.DASHBOARD} replace />} />
          <Route path="*" element={<div>Not Found</div>} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
