import { useState } from 'react'
import type { FormEvent } from 'react'
import { api, errorMessage, setCsrf } from '../api'
import { Alert, Button, Field } from '../components/ui'
import { themeLabel, useTheme } from '../theme'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [ticket, setTicket] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { cycleMode, mode } = useTheme()

  function restartLogin() {
    setTicket('')
    setCode('')
    setError('')
  }

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      if (!ticket) {
        const r = await api.post<{ ticket: string }>('/api/auth/login', { username, password })
        setTicket(r.ticket)
      } else {
        const r = await api.post<{ csrf: string }>('/api/auth/totp', { ticket, code })
        setCsrf(r.csrf)
        onLogin()
      }
    } catch (err: unknown) {
      setError(errorMessage(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="app-shell grid min-h-screen lg:grid-cols-[minmax(0,1.05fr)_minmax(420px,.95fr)]">
      <section className="relative hidden overflow-hidden p-10 lg:flex lg:flex-col lg:justify-between xl:p-16">
        <div className="absolute -left-20 top-24 h-80 w-80 rounded-full bg-cyan-500/10 blur-3xl" />
        <div className="relative flex items-center gap-3">
          <div className="brand-mark text-xl font-black">W</div>
          <div className="text-base font-bold tracking-tight text-slate-100">WireGuard Manager</div>
        </div>
        <div className="relative max-w-xl">
          <div className="eyebrow mb-5">私有网络，清晰掌控</div>
          <h1 className="max-w-lg text-6xl font-black leading-[.98] tracking-[-.065em] text-slate-100">
            你的网络，<br /><span className="text-cyan-300">安静守护。</span>
          </h1>
          <p className="mt-7 max-w-md text-base leading-7 text-slate-500">在一个简洁的控制台中管理接口、Peer 和加密客户端身份。</p>
          <div className="mt-12 grid max-w-md grid-cols-3 gap-3">
            {['接口', 'Peers', '加密密钥库'].map((label, index) => (
              <div key={label} className="border-l-2 border-cyan-500/40 pl-3">
                <div className="text-xl font-bold text-slate-200">{['01', '02', '03'][index]}</div>
                <div className="mt-1 text-[10px] uppercase tracking-wider text-slate-500">{label}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="relative flex items-center justify-between text-xs text-slate-600"><span>WIREGUARD / 安全管理</span><span>v1.0.0</span></div>
      </section>
      <section className="flex min-h-screen items-center justify-center p-5 sm:p-10">
        <div className="w-full max-w-md">
          <div className="mb-8 flex items-center justify-between lg:hidden">
            <div className="flex items-center gap-3"><div className="brand-mark text-lg font-black">W</div><span className="font-bold text-slate-100">WireGuard Manager</span></div>
            <button onClick={cycleMode} className="theme-chip rounded-lg px-2.5 py-1.5 text-xs">◐ {themeLabel(mode)}</button>
          </div>
          <div className="surface-card rounded-3xl p-7 sm:p-9">
            <div className="mb-8">
              <div className="eyebrow mb-3">安全访问</div>
              <h2 className="text-2xl font-bold tracking-tight text-slate-100">欢迎回来</h2>
              <p className="mt-2 text-sm text-slate-500">{ticket ? '打开验证器，输入 6 位验证码。' : '使用管理员账号进入控制台。'}</p>
            </div>
            {error && <Alert kind="error">{error}</Alert>}
            <form onSubmit={submit}>
              {!ticket ? (
                <>
                  <Field label="用户名"><input className="w-full" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required /></Field>
                  <Field label="密码"><input className="w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
                </>
              ) : (
                <Field label="两步验证码 (TOTP)">
                  <input className="w-full text-center text-2xl tracking-[0.5em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoFocus placeholder="······" required />
                </Field>
              )}
              <Button type="submit" disabled={busy} className="mt-1 w-full">
                {busy ? '验证中…' : ticket ? '进入控制台' : '继续'}
              </Button>
            </form>
            {ticket && (
              <button type="button" onClick={restartLogin} className="mt-4 w-full text-xs text-slate-500 hover:text-slate-300">
                返回重新登录
              </button>
            )}
            <div className="mt-7 flex items-center gap-2 text-[11px] text-slate-600"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />本地会话 · CSRF 保护已启用</div>
          </div>
        </div>
      </section>
    </div>
  )
}
