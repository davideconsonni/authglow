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

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5,
      retry: 1,
    },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (!isAuthenticated) {
    return <Navigate to={ROUTES.AUTH.LOGIN} replace />
  }
  return <>{children}</>
}

function GuestRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  if (isAuthenticated) {
    return <Navigate to={ROUTES.DASHBOARD} replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route
            path={ROUTES.AUTH.LOGIN}
            element={
              <GuestRoute>
                <LoginPage />
              </GuestRoute>
            }
          />
          <Route
            path={ROUTES.AUTH.REGISTER}
            element={
              <GuestRoute>
                <RegisterPage />
              </GuestRoute>
            }
          />
          <Route
            path={ROUTES.AUTH.FORGOT_PASSWORD}
            element={
              <GuestRoute>
                <ForgotPasswordPage />
              </GuestRoute>
            }
          />
          <Route
            path={ROUTES.AUTH.RESET_PASSWORD}
            element={
              <GuestRoute>
                <ResetPasswordPage />
              </GuestRoute>
            }
          />
          <Route
            path={ROUTES.AUTH.MFA_VERIFY}
            element={<MFAVerifyPage />}
          />
          <Route
            path={ROUTES.AUTH.VERIFY_EMAIL}
            element={<EmailVerifiedPage />}
          />
          <Route
            path={ROUTES.OAUTH_CONSENT}
            element={<OAuthConsentPage />}
          />
          <Route
            path={ROUTES.SETUP}
            element={<div>Setup Page</div>}
          />

          <Route
            element={
              <ProtectedRoute>
                <AppShell />
              </ProtectedRoute>
            }
          >
            <Route path={ROUTES.DASHBOARD} element={<div>Dashboard Page</div>} />
            <Route path={ROUTES.PROFILE} element={<div>Profile Page</div>} />
            <Route path={ROUTES.SECURITY} element={<SecurityPage />} />
            <Route path={ROUTES.SESSIONS} element={<div>Sessions Page</div>} />
            <Route path={ROUTES.API_KEYS} element={<div>API Keys Page</div>} />
            <Route path={ROUTES.ADMIN.DASHBOARD} element={<div>Admin Dashboard Page</div>} />
            <Route path={ROUTES.ADMIN.USERS} element={<div>Admin Users Page</div>} />
            <Route path={ROUTES.ADMIN.OAUTH_CLIENTS} element={<div>Admin OAuth Clients Page</div>} />
            <Route path={ROUTES.ADMIN.SESSIONS} element={<div>Admin Sessions Page</div>} />
            <Route path={ROUTES.ADMIN.CONSENTS} element={<div>Admin Consents Page</div>} />
            <Route path={ROUTES.ADMIN.API_KEYS} element={<div>Admin API Keys Page</div>} />
            <Route path={ROUTES.ADMIN.RBAC} element={<div>Admin RBAC Page</div>} />
            <Route path={ROUTES.ADMIN.JWK_KEYS} element={<div>Admin JWK Keys Page</div>} />
            <Route path={ROUTES.ADMIN.PASSWORD_RESETS} element={<div>Admin Password Resets Page</div>} />
            <Route path={ROUTES.ADMIN.PLAYGROUND} element={<div>Admin Playground Page</div>} />
          </Route>

          <Route path="/" element={<Navigate to={ROUTES.DASHBOARD} replace />} />
          <Route path="*" element={<div>Not Found</div>} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
