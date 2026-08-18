import { Outlet } from 'react-router-dom'
import { Sidebar } from '../../components/layout/Sidebar'
import { TopBar } from '../../components/layout/TopBar'
import { Banner } from '../../components/shared/Banner'
import { useDemoMeta } from '../../hooks/useDemoMeta'

export function AppShell() {
  const { meta } = useDemoMeta()

  return (
    <div className="flex h-screen overflow-hidden bg-bg-primary">
      <Sidebar />
      <div className="flex flex-1 flex-col overflow-hidden">
        <TopBar />
        {meta.demo_mode && (
          <div className="border-b border-semantic-warning/20 bg-semantic-warning/10 px-6 py-2">
            <Banner variant="warning" size="sm" data-testid="demo-mode-banner">
              {meta.demo_banner_text || 'Demo environment — accounts and data are reset on every server restart.'}
            </Banner>
          </div>
        )}
        <main className="flex-1 overflow-y-auto scrollbar-dark">
          <div className="mx-auto max-w-6xl px-6 py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
