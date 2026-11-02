import { useState } from 'react'
import type { FormEvent } from 'react'
import { api, errorMessage } from '../api'
import { Alert, Button, Field } from '../components/ui'
import { themeLabel, useTheme } from '../theme'

export default function Setup({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [enrolling, setEnrolling] = useState(false)
  const [secret, setSecret] = useState('')
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { cycleMode, mode } = useTheme()

  async function create(e: FormEvent) {
    e.preventDefault(); setError(''); setBusy(true)
    try {
      const r = await api.post<{ secret: string; qr_data_url: string }>('/api/setup', { username, password })
      setSecret(r.secret); setQr(r.qr_data_url); setEnrolling(true)
    } catch (err: unknown) { setError(errorMessage(err)) } finally { setBusy(false) }
  }
  async function verify(e: FormEvent) {
    e.preventDefault(); setError(''); setBusy(true)
    try { await api.post('/api/setup/verify', { code }); onDone() } catch (err: unknown) { setError(errorMessage(err)) } finally { setBusy(false) }
  }

  return (
    <div className="app-shell flex min-h-screen items-center justify-center p-5 sm:p-10">
      <div className="safe-corner absolute"><button onClick={cycleMode} className="theme-chip rounded-lg px-2.5 py-1.5 text-xs">◐ {themeLabel(mode)}</button></div>
      <div className="grid w-full max-w-5xl overflow-hidden rounded-3xl border border-slate-800 bg-slate-900/60 shadow-2xl lg:grid-cols-[.85fr_1.15fr]">
        <div className="hidden flex-col justify-between bg-cyan-500/10 p-10 lg:flex">
          <div className="flex items-center gap-3"><div className="brand-mark text-lg font-black">W</div><span className="font-bold text-slate-100">WireGuard Manager</span></div>
          <div><div className="eyebrow mb-4">首次使用</div><h1 className="text-5xl font-black leading-none tracking-[-.06em] text-slate-100">建立你的<br /><span className="text-cyan-300">安全基础。</span></h1><p className="mt-6 max-w-xs text-sm leading-6 text-slate-500">创建管理员账号并绑定第二重验证，之后即可管理网络。</p></div>
          <div className="text-[10px] uppercase tracking-[.16em] text-slate-600">本地管理 / 加密存储</div>
        </div>
        <div className="p-7 sm:p-12">
          <div className="mb-8 lg:hidden"><div className="eyebrow mb-3">首次使用</div><h1 className="text-2xl font-bold text-slate-100">初始化控制台</h1></div>
          <div className="mb-8 hidden lg:block"><div className="eyebrow mb-3">管理员设置</div><h2 className="text-2xl font-bold tracking-tight text-slate-100">创建管理员</h2><p className="mt-2 text-sm text-slate-500">初始化账号并绑定 TOTP 验证器。</p></div>
          {error && <Alert kind="error">{error}</Alert>}
          {!enrolling ? (
            <form onSubmit={create}>
              <Field label="管理员用户名"><input className="w-full" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus required /></Field>
              <Field label="密码（至少 8 位）"><input className="w-full" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required /></Field>
               <p className="mb-4 text-xs text-slate-500">绑定中断时，请输入原管理员账号和密码恢复二维码；不会覆盖已有账号。</p>
               <Button type="submit" disabled={busy} className="w-full">{busy ? '处理中…' : '创建 / 恢复绑定'}</Button>
            </form>
          ) : (
            <div>
              <div className="mb-6 flex gap-3 text-sm text-slate-400"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full bg-cyan-500/10 text-cyan-300">1</span><span>使用验证器 App 扫描二维码，然后输入显示的 6 位验证码。</span></div>
              <div className="mb-5 flex justify-center rounded-2xl bg-white p-4"><img src={qr} alt="TOTP QR" width={200} height={200} /></div>
              <p className="mb-5 text-xs leading-5 text-slate-500">无法扫码？手动输入密钥：<code className="select-all break-all text-cyan-300">{secret}</code></p>
              <form onSubmit={verify}>
                <Field label="验证码"><input className="w-full text-center text-2xl tracking-[0.5em]" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoFocus placeholder="······" required /></Field>
                <Button type="submit" disabled={busy} className="w-full">{busy ? '验证中…' : '完成初始化'}</Button>
              </form>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
