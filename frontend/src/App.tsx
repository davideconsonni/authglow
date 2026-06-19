import { lazy, Suspense, useState, useEffect, useRef } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AppShell } from '@/components/layout/AppShell'
import { LoadingState } from '@/components/shared/LoadingState'
import { ROUTES } from '@/lib/constants'
import { useAuth } from '@/hooks/useAuth'
import { useAuthStore } from '@/stores/authStore'
import { useTheme } from '@/hooks/useTheme'
import { CommandPalette } from '@/components/admin/CommandPalette'
import { api } from '@/lib/api'

import { LoginPage } from '@/pages/auth/LoginPage'
import { RegisterPage } from '@/pages/auth/RegisterPage'
import { ForgotPasswordPage } from '@/pages/auth/ForgotPasswordPage'
import { ResetPasswordPage } from '@/pages/auth/ResetPasswordPage'
import { EmailVerifiedPage } from '@/pages/auth/EmailVerifiedPage'
import { OAuthAuthorizePage } from '@/pages/OAuthAuthorizePage'
import { DeviceVerificationPage } from '@/pages/DeviceVerificationPage'
import { MFAVerifyPage } from '@/pages/auth/MFAVerifyPage'
import { DashboardPage } from '@/pages/DashboardPage'
import { ProfilePage } from '@/pages/ProfilePage'
import { SessionsPage } from '@/pages/SessionsPage'
import { ApiKeysPage } from '@/pages/ApiKeysPage'
import { DeviceAuthorizationsPage } from '@/pages/DeviceAuthorizationsPage'
import { SetupPage } from '@/pages/SetupPage'
import { NotFoundPage } from '@/pages/NotFoundPage'
import { ToastContainer } from '@/components/shared/Toast'

const SecurityPage = lazy(() =>
  import('@/pages/SecurityPage').then((m) => ({ default: m.SecurityPage })),
)

const AdminDashboardPage = lazy(() =>
  import('@/pages/admin/AdminDashboardPage').then((m) => ({ default: m.AdminDashboardPage })),
)
const AdminUsersPage = lazy(() =>
  import('@/pages/admin/AdminUsersPage').then((m) => ({ default: m.AdminUsersPage })),
)
const AdminOAuthClientsPage = lazy(() =>
  import('@/pages/admin/AdminOAuthClientsPage').then((m) => ({ default: m.AdminOAuthClientsPage })),
)
const AdminSessionsPage = lazy(() =>
  import('@/pages/admin/AdminSessionsPage').then((m) => ({ default: m.AdminSessionsPage })),
)
const AdminConsentsPage = lazy(() =>
  import('@/pages/admin/AdminConsentsPage').then((m) => ({ default: m.AdminConsentsPage })),
)
const AdminApiKeysPage = lazy(() =>
  import('@/pages/admin/AdminApiKeysPage').then((m) => ({ default: m.AdminApiKeysPage })),
)
const AdminRbacPage = lazy(() =>
  import('@/pages/admin/AdminRbacPage').then((m) => ({ default: m.AdminRbacPage })),
)
const AdminJwkKeysPage = lazy(() =>
  import('@/pages/admin/AdminJwkKeysPage').then((m) => ({ default: m.AdminJwkKeysPage })),
)
const AdminPasswordResetsPage = lazy(() =>
  import('@/pages/admin/AdminPasswordResetsPage').then((m) => ({ default: m.AdminPasswordResetsPage })),
)
const AdminPlaygroundPage = lazy(() =>
  import('@/pages/admin/AdminPlaygroundPage').then((m) => ({ default: m.AdminPlaygroundPage })),
)
const AdminFederationPage = lazy(() =>
  import('@/pages/admin/AdminFederationPage').then((m) => ({ default: m.AdminFederationPage })),
)
const AdminDeviceAuthsPage = lazy(() =>
  import('@/pages/admin/AdminDeviceAuthsPage').then((m) => ({ default: m.AdminDeviceAuthsPage })),
)
const DeviceAuthNewTool = lazy(() =>
  import('@/pages/admin/DeviceAuthNewTool').then((m) => ({ default: m.DeviceAuthNewTool })),
)
const AdminSettingsPage = lazy(() =>
  import('@/pages/admin/AdminSettingsPage').then((m) => ({ default: m.AdminSettingsPage })),
)
const AdminRateLimitsPage = lazy(() =>
  import('@/pages/admin/AdminRateLimitsPage').then((m) => ({ default: m.AdminRateLimitsPage })),
)

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { staleTime: 1000 * 60 * 5, retry: 1 },
  },
})

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  const hydrated = useAuthStore((s) => s._hydrated)
  const probed = useRef(false)
  const [probing, setProbing] = useState(true)

  useEffect(() => {
    const handler = () => {
      useAuthStore.getState().setAuthenticated(false)
    }
    window.addEventListener('auth:session-expired', handler)
    return () => window.removeEventListener('auth:session-expired', handler)
  }, [])

  useEffect(() => {
    if (!hydrated || probed.current) return
    probed.current = true
    // Always verify the session with the server, even when isAuthenticated is
    // true from the persisted store. The persisted value can be stale (e.g.,
    // access/refresh cookies expired) and the first protected query would
    // 401, triggering an immediate kick-out. One roundtrip on mount is
    // cheaper than the UX of being silently logged out.
    setProbing(true)
    useAuthStore.getState().fetchCurrentUser()
      .finally(() => setProbing(false))
  }, [hydrated])

  if (!hydrated || probing) return <LoadingState />
  if (!isAuthenticated) return <Navigate to={ROUTES.AUTH.LOGIN} replace />
  return <>{children}</>
}

function GuestRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth()
  const hydrated = useAuthStore((s) => s._hydrated)
  if (!hydrated) return <LoadingState />
  if (isAuthenticated) return <Navigate to={ROUTES.DASHBOARD} replace />
  return <>{children}</>
}

function SetupGuard({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const checked = useRef(false)
  const [setupStatus, setSetupStatus] = useState<{ loading: boolean; needsSetup: boolean }>({
    loading: true,
    needsSetup: false,
  })

  useEffect(() => {
    if (location.pathname === ROUTES.SETUP) {
      setSetupStatus({ loading: false, needsSetup: false })
      return
    }
    if (checked.current) return
    checked.current = true
    api.get<{ needs_setup: boolean }>('/api/setup/check')
      .then((data) => setSetupStatus({ loading: false, needsSetup: data.needs_setup }))
      .catch(() => setSetupStatus({ loading: false, needsSetup: false }))
  }, [location.pathname])

  if (location.pathname === ROUTES.SETUP) return <>{children}</>
  if (setupStatus.loading) return <LoadingState />
  if (setupStatus.needsSetup) return <Navigate to={ROUTES.SETUP} replace />
  return <>{children}</>
}

function LazyFallback() {
  return <LoadingState />
}

function ThemeInitializer({ children }: { children: React.ReactNode }) {
  useTheme()
  return <>{children}</>
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ThemeInitializer>
        <SetupGuard>
        <Routes>
          <Route path={ROUTES.AUTH.LOGIN} element={<GuestRoute><LoginPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.REGISTER} element={<GuestRoute><RegisterPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.FORGOT_PASSWORD} element={<GuestRoute><ForgotPasswordPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.RESET_PASSWORD} element={<GuestRoute><ResetPasswordPage /></GuestRoute>} />
          <Route path={ROUTES.AUTH.MFA_VERIFY} element={<MFAVerifyPage />} />
          <Route path={ROUTES.AUTH.VERIFY_EMAIL} element={<EmailVerifiedPage />} />
          <Route path={ROUTES.OAUTH_AUTHORIZE} element={<OAuthAuthorizePage />} />
          <Route path={ROUTES.OAUTH_DEVICE_VERIFY} element={<DeviceVerificationPage />} />
          <Route path={ROUTES.SETUP} element={<SetupPage />} />

          <Route element={<ProtectedRoute><AppShell /></ProtectedRoute>}>
            <Route path={ROUTES.DASHBOARD} element={<DashboardPage />} />
            <Route path={ROUTES.PROFILE} element={<ProfilePage />} />
            <Route path={ROUTES.SECURITY} element={<Suspense fallback={<LazyFallback />}><SecurityPage /></Suspense>} />
            <Route path={ROUTES.SESSIONS} element={<SessionsPage />} />
            <Route path={ROUTES.API_KEYS} element={<ApiKeysPage />} />
            <Route path={ROUTES.DEVICE_AUTHORIZATIONS} element={<DeviceAuthorizationsPage />} />
            <Route path={ROUTES.ADMIN.DASHBOARD} element={<Suspense fallback={<LazyFallback />}><AdminDashboardPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.USERS} element={<Suspense fallback={<LazyFallback />}><AdminUsersPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.OAUTH_CLIENTS} element={<Suspense fallback={<LazyFallback />}><AdminOAuthClientsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.SESSIONS} element={<Suspense fallback={<LazyFallback />}><AdminSessionsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.CONSENTS} element={<Suspense fallback={<LazyFallback />}><AdminConsentsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.API_KEYS} element={<Suspense fallback={<LazyFallback />}><AdminApiKeysPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.RBAC} element={<Suspense fallback={<LazyFallback />}><AdminRbacPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.JWK_KEYS} element={<Suspense fallback={<LazyFallback />}><AdminJwkKeysPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.PASSWORD_RESETS} element={<Suspense fallback={<LazyFallback />}><AdminPasswordResetsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.PLAYGROUND} element={<Suspense fallback={<LazyFallback />}><AdminPlaygroundPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.FEDERATION} element={<Suspense fallback={<LazyFallback />}><AdminFederationPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.SETTINGS} element={<Suspense fallback={<LazyFallback />}><AdminSettingsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.RATE_LIMITS} element={<Suspense fallback={<LazyFallback />}><AdminRateLimitsPage /></Suspense>} />
            <Route path={ROUTES.ADMIN.DEVICE_AUTHORIZATIONS_NEW} element={<Suspense fallback={<LazyFallback />}><DeviceAuthNewTool /></Suspense>} />
            <Route path={ROUTES.ADMIN.DEVICE_AUTHORIZATIONS} element={<Suspense fallback={<LazyFallback />}><AdminDeviceAuthsPage /></Suspense>} />
          </Route>

          <Route path="/" element={<Navigate to={ROUTES.DASHBOARD} replace />} />
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
        <CommandPalette />
        </SetupGuard>
        <ToastContainer />
        </ThemeInitializer>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

export default App
