import { Navigate, Route, Routes } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { api, setCsrf } from './api'
import Layout from './components/Layout'
import Login from './pages/Login'
import Setup from './pages/Setup'
import Dashboard from './pages/Dashboard'
import Peers from './pages/Peers'
import ConfigEditor from './pages/ConfigEditor'
import KeyVault from './pages/KeyVault'
import Settings from './pages/Settings'

type Phase = 'loading' | 'setup' | 'login' | 'app'

export default function App() {
  const [phase, setPhase] = useState<Phase>('loading')

  useEffect(() => {
    ;(async () => {
      try {
        const s = await api.get<{ needs_setup: boolean }>('/api/setup/status')
        if (s.needs_setup) {
          setPhase('setup')
          return
        }
        const me = await api.get<{ csrf?: string }>('/api/me')
        // 恢复内存中的 CSRF（刷新页面后丢失，见 handleMe）
        if (me.csrf) setCsrf(me.csrf)
        setPhase('app')
      } catch {
        setPhase('login')
      }
    })()
  }, [])

  if (phase === 'loading') {
    return (
      <div className="app-shell flex min-h-screen items-center justify-center">
        <div className="flex items-center gap-3 text-sm text-slate-500"><span className="brand-mark h-9 w-9 animate-pulse text-sm font-black">W</span>正在连接控制平面…</div>
      </div>
    )
  }
  if (phase === 'setup') return <Setup onDone={() => setPhase('login')} />
  if (phase === 'login') return <Login onLogin={() => setPhase('app')} />

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/peers" element={<Peers />} />
        <Route path="/config" element={<ConfigEditor />} />
        <Route path="/keys" element={<KeyVault />} />
        <Route path="/settings" element={<Settings onLogout={() => setPhase('login')} />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}
