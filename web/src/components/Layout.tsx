import { NavLink, useLocation } from 'react-router-dom'
import type { ReactNode } from 'react'
import { api, setCsrf } from '../api'
import { themeLabel, useTheme } from '../theme'

const nav = [
  { to: '/dashboard', label: '总览', sub: '运行概况', icon: '▦' },
  { to: '/peers', label: '对端', sub: '连接管理', icon: '⇄' },
  { to: '/keys', label: '密钥', sub: '密钥管理', icon: '⚿' },
  { to: '/config', label: '接口', sub: '配置管理', icon: '≡' },
  { to: '/settings', label: '设置', sub: '系统设置', icon: '⚙' },
]

export default function Layout({ children }: { children: ReactNode }) {
  const location = useLocation()
  const { mode, cycleMode } = useTheme()
  const mobileTitle = nav.find((n) => n.to === location.pathname.slice(1))?.label ?? '总览'

  async function logout() {
    try {
      await api.post('/api/auth/logout')
      setCsrf('')
      window.location.reload()
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="app-shell flex min-h-screen flex-col lg:flex-row">
      <aside className="app-sidebar flex min-w-0 w-full shrink-0 flex-col border-b lg:sticky lg:top-0 lg:h-screen lg:w-65 lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-3 px-5 py-5 lg:px-6 lg:py-7">
          <div className="brand-mark text-xl font-black">W</div>
          <div>
            <div className="text-base font-bold tracking-tight text-slate-100">WireGuard</div>
            <div className="text-[10px] font-semibold uppercase tracking-[.16em] text-slate-500">管理控制台</div>
          </div>
        </div>
        <div className="hidden px-6 pb-6 lg:block">
          <div className="rounded-xl border border-slate-800 bg-slate-800/60 px-3 py-2.5">
            <div className="flex items-center gap-2 text-xs font-medium text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              控制平面已就绪
            </div>
            <div className="mt-1 text-[11px] text-slate-500">WireGuard 服务管理</div>
          </div>
        </div>
        <nav className="flex min-w-0 gap-1 overflow-x-auto px-3 pb-3 lg:block lg:flex-1 lg:space-y-1 lg:px-3">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex min-w-max items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-all lg:px-3.5 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-300 shadow-sm'
                    : 'text-slate-500 hover:bg-slate-800/60 hover:text-slate-200'
                }`
              }
            >
              <span className="grid h-7 w-7 place-items-center rounded-lg bg-slate-800/60 font-mono text-sm text-slate-400">{item.icon}</span>
              <span className="hidden text-left lg:block">
                <span className="block font-medium">{item.label}</span>
                <span className="block text-[10px] text-slate-600">{item.sub}</span>
              </span>
              <span className="lg:hidden">{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="hidden space-y-2 px-4 pb-5 lg:block">
          <button onClick={cycleMode} className="theme-chip flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-xs transition-colors" title="切换主题">
            <span className="flex items-center gap-2"><span className="text-sm">◐</span>{themeLabel(mode)}</span>
            <span className="text-[10px] text-slate-500">切换</span>
          </button>
          <button onClick={logout} className="w-full rounded-xl border border-slate-800 px-3 py-2.5 text-left text-sm text-slate-500 transition-colors hover:border-red-900 hover:text-red-400">
            <span className="mr-2">↗</span>退出登录
          </button>
        </div>
      </aside>
      <main className="app-main min-w-0 flex-1 px-4 py-6 sm:px-6 lg:px-10 lg:py-10">
        <div className="mb-5 flex min-w-0 items-center justify-between gap-3 lg:hidden">
          <span className="text-xs font-semibold uppercase tracking-[.15em] text-slate-500">{mobileTitle}</span>
          <div className="flex gap-2">
            <button onClick={cycleMode} className="theme-chip rounded-lg px-2.5 py-1.5 text-xs">◐ {themeLabel(mode)}</button>
            <button onClick={logout} className="rounded-lg border border-slate-800 px-2.5 py-1.5 text-xs text-slate-500">退出</button>
          </div>
        </div>
        {children}
      </main>
    </div>
  )
}
