import { useEffect, useState } from 'react'
import type { FormEvent, ReactNode } from 'react'
import { api, errorMessage, setCsrf } from '../api'
import { Button, Card, Field, Modal, PageTitle, Toast } from '../components/ui'

function SettingIcon({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl border border-slate-800 bg-slate-800/60 text-base text-cyan-300 ${className}`}>
      {children}
    </span>
  )
}

function SettingsSectionHeading({ number, eyebrow, title, desc }: { number: string; eyebrow: string; title: string; desc: string }) {
  return (
    <div className="mb-4 flex items-end justify-between gap-4">
      <div>
        <div className="eyebrow mb-2">{number} / {eyebrow}</div>
        <h2 className="text-xl font-semibold tracking-tight text-slate-100">{title}</h2>
        <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-500">{desc}</p>
      </div>
      <span className="hidden font-mono text-xs text-slate-600 sm:block">{number}</span>
    </div>
  )
}

function SettingsCardHeader({ icon, tag, title, desc }: { icon: ReactNode; tag: string; title: string; desc: string }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-slate-800 px-5 py-5 sm:px-6">
      <div className="flex min-w-0 items-start gap-3">
        <SettingIcon>{icon}</SettingIcon>
        <div className="min-w-0">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <h3 className="text-base font-semibold text-slate-100">{title}</h3>
            <span className="rounded-md border border-slate-800 px-1.5 py-0.5 font-mono text-[9px] font-semibold tracking-[.12em] text-slate-500">{tag}</span>
          </div>
          <p className="max-w-xl text-xs leading-5 text-slate-500">{desc}</p>
        </div>
      </div>
    </div>
  )
}

function AboutItem({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="flex gap-3 px-5 py-5 sm:px-6">
      <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-slate-800/60 font-mono text-sm text-slate-400">{icon}</span>
      <div className="min-w-0">
        <div className="text-sm font-medium text-slate-200">{title}</div>
        <div className="mt-1 text-xs leading-5 text-slate-500">{children}</div>
      </div>
    </div>
  )
}

export default function Settings({ onLogout }: { onLogout: () => void }) {
  return (
    <div className="mx-auto w-full max-w-3xl">
      <PageTitle
        title="设置"
        desc="控制默认网络行为，管理账户安全与运行环境。"
        right={
          <span className="inline-flex items-center gap-2 rounded-xl border border-slate-800 bg-slate-800/60 px-3 py-2 text-xs text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            仅管理员可见
          </span>
        }
      />

      <div className="min-w-0 space-y-8">
          <section id="network-defaults" className="scroll-mt-8">
            <SettingsSectionHeading
              number="01"
              eyebrow="NETWORK DEFAULTS"
              title="网络偏好"
              desc="为新建 Peer 提供默认连接信息，并决定服务启动时是否自动拉起接口。"
            />
            <Card className="overflow-hidden">
              <div className="flex items-start justify-between gap-4 border-b border-slate-800 bg-slate-800/60 px-5 py-4 sm:px-6">
                <div className="flex items-center gap-3">
                  <SettingIcon className="h-9 w-9 text-sm">↗</SettingIcon>
                  <div>
                    <h3 className="text-sm font-semibold text-slate-100">默认连接参数</h3>
                    <p className="mt-1 text-xs text-slate-500">新增客户端时自动带入的基础配置</p>
                  </div>
                </div>
                <span className="rounded-lg border border-slate-700 px-2 py-1 font-mono text-[10px] text-slate-500">app.yaml</span>
              </div>
              <div className="p-5 sm:p-6">
                <ServerDefaults />
              </div>
            </Card>
          </section>

          <section id="account-security" className="scroll-mt-8">
            <SettingsSectionHeading
              number="02"
              eyebrow="ACCOUNT SECURITY"
              title="账号安全"
              desc="密码和两步验证共同保护管理控制台。敏感操作需要再次确认身份。"
            />
            <div className="grid gap-6">
              <Card className="overflow-hidden">
                <SettingsCardHeader
                  icon="⌑"
                  tag="PASSWORD"
                  title="修改密码"
                  desc="更新管理员登录密码，建议使用未在其他服务重复使用的长密码。"
                />
                <div className="p-5 sm:p-6">
                  <ChangePassword />
                </div>
              </Card>

              <Card className="overflow-hidden">
                <SettingsCardHeader
                  icon="◎"
                  tag="AUTHENTICATOR"
                  title="两步验证 (TOTP)"
                  desc="丢失验证器时，可使用当前密码生成新的二维码重新绑定。"
                />
                <div className="p-5 sm:p-6">
                  <TwoFA onLogout={onLogout} />
                </div>
              </Card>
            </div>
          </section>

          <section id="about-console" className="scroll-mt-8">
            <SettingsSectionHeading
              number="03"
              eyebrow="SYSTEM NOTES"
              title="关于控制台"
              desc="与数据存储、审计记录和运行权限相关的部署信息。"
            />
            <Card className="overflow-hidden">
              <div className="grid divide-y divide-slate-800 md:grid-cols-3 md:divide-x md:divide-y-0">
                <AboutItem icon="▧" title="凭证与密钥">
                  users.yaml、加密 vault.yaml、master.key（0600）
                </AboutItem>
                <AboutItem icon="⌁" title="审计记录">
                  所有敏感操作均记录于 audit.log
                </AboutItem>
                <AboutItem icon="⌘" title="运行权限">
                  wg 命令需要 root 或 CAP_NET_ADMIN 权限
                </AboutItem>
              </div>
            </Card>
          </section>
      </div>
    </div>
  )
}

function ServerDefaults() {
  const [endpoint, setEndpoint] = useState('')
  const [autoUp, setAutoUp] = useState(true)
  const [msg, setMsg] = useState<{ kind: 'error' | 'ok'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    api.get<{ server_endpoint: string; auto_up: boolean }>('/api/settings/defaults').then((r) => {
      setEndpoint(r.server_endpoint ?? '')
      setAutoUp(!!r.auto_up)
    }).catch(() => {})
  }, [])

  async function save() {
    if (busy) return
    setMsg(null)
    setBusy(true)
    try {
      await api.post('/api/settings/defaults', {
        server_endpoint: endpoint.trim(),
        auto_up: autoUp,
      })
      setMsg({ kind: 'ok', text: '已保存，下次程序启动生效' })
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}
      <div className="grid gap-2 lg:grid-cols-[minmax(0,1.1fr)_minmax(280px,.9fr)] lg:gap-5">
        <Field label="服务端 Endpoint（新增 Peer 时自动填入）">
          <input
            className="w-full font-mono"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="vpn.example.com"
          />
          <span className="mt-2 block text-xs leading-5 text-slate-600">填写公网域名或IP。</span>
        </Field>
        <label className="mb-5 flex cursor-pointer items-start gap-3 rounded-xl border border-slate-800 bg-slate-800/60 p-4 transition-colors hover:border-slate-700">
          <input
            type="checkbox"
            checked={autoUp}
            onChange={(e) => setAutoUp(e.target.checked)}
            className="mt-1 h-4 w-4 shrink-0 accent-cyan-500"
          />
          <span>
            <span className="block text-sm font-medium text-slate-200">启动时自动开启接口</span>
            <span className="mt-1 block text-xs leading-5 text-slate-500">程序启动时对每个配置文件执行 wg-quick up，已运行的接口会自动跳过。</span>
          </span>
        </label>
      </div>
      <div className="flex flex-col gap-3 border-t border-slate-800 pt-5 sm:flex-row sm:items-center sm:justify-between">
        <span className="flex items-center gap-2 text-xs text-slate-600"><span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />更改保存至本地配置文件</span>
        <Button onClick={save} disabled={busy}>{busy ? '保存中…' : '保存设置'}</Button>
      </div>
    </div>
  )
}

function ChangePassword() {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [msg, setMsg] = useState<{ kind: 'error' | 'ok'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (busy) return
    setMsg(null)
    setBusy(true)
    try {
      await api.post('/api/settings/password', { current_password: current, new_password: next })
      setMsg({ kind: 'ok', text: '密码已更新' })
      setCurrent('')
      setNext('')
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}
      <form onSubmit={submit}>
        <div className="grid gap-x-4 sm:grid-cols-2">
          <Field label="当前密码">
            <input className="w-full" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} required />
          </Field>
          <Field label="新密码（至少 8 位）">
            <input className="w-full" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} required />
          </Field>
        </div>
        <div className="flex flex-col gap-3 border-t border-slate-800 pt-5 sm:flex-row sm:items-center sm:justify-between">
          <span className="text-xs leading-5 text-slate-600">更新后当前密码立即失效。</span>
          <Button type="submit" disabled={busy}>{busy ? '更新中…' : '更新密码'}</Button>
        </div>
      </form>
    </div>
  )
}

function TwoFA({ onLogout }: { onLogout: () => void }) {
  const [pw, setPw] = useState('')
  const [enroll, setEnroll] = useState<{ secret: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [msg, setMsg] = useState<{ kind: 'error' | 'ok'; text: string } | null>(null)
  const [busy, setBusy] = useState(false)

  async function reset() {
    if (!confirm('生成新的 2FA 绑定二维码？验证新二维码成功前，旧验证器保持有效；其他会话将失效。')) return
    setMsg(null)
    setBusy(true)
    try {
      const r = await api.post<{ secret: string; qr_data_url: string }>('/api/settings/totp/reset', { password: pw })
      setEnroll({ secret: r.secret, qr: r.qr_data_url })
      setPw('')
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  async function verify() {
    setMsg(null)
    setBusy(true)
    try {
      await api.post('/api/settings/totp/verify', { code })
      setMsg({ kind: 'ok', text: '两步验证已重新启用' })
      setEnroll(null)
      setCode('')
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  async function logoutEverywhere() {
    if (busy) return
    setBusy(true)
    try {
      await api.post('/api/auth/logout')
      setCsrf('')
      onLogout()
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}
      <div className="mb-5 rounded-xl border border-slate-800 bg-slate-800/60 p-4">
        <div className="flex items-start gap-3">
          <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-cyan-500/10 font-mono text-xs text-cyan-300">01</span>
          <div>
            <div className="text-sm font-medium text-slate-200">重新绑定验证器</div>
            <p className="mt-1 text-xs leading-5 text-slate-500">输入当前密码后生成新的 TOTP 二维码，扫码并验证一次即可完成绑定。</p>
          </div>
        </div>
      </div>
      <Field label="当前密码">
        <input className="w-full" type="password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} placeholder="输入当前密码以验证身份" />
      </Field>
      <div className="flex flex-col gap-2 border-t border-slate-800 pt-5 sm:flex-row">
        <Button variant="danger" onClick={reset} disabled={!pw || busy} className="sm:flex-1">
          重置 2FA
        </Button>
        <Button variant="ghost" onClick={logoutEverywhere} disabled={busy} className="sm:flex-1">
          {busy ? '处理中…' : '退出登录'}
        </Button>
      </div>
      <p className="mt-3 text-[11px] leading-5 text-slate-600">退出登录会使当前会话失效，适合在共享设备上使用。</p>

      <Modal
        open={!!enroll}
        onClose={() => setEnroll(null)}
        title="重新绑定两步验证"
      >
        {enroll && (
          <div className="space-y-5">
            <div className="flex items-start gap-3">
              <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-cyan-500/10 font-mono text-xs text-cyan-300">01</span>
              <div>
                <div className="text-sm font-medium text-slate-200">使用验证器扫描</div>
                <p className="mt-1 text-xs leading-5 text-slate-500">扫码并验证后才会替换旧验证器。刷新或关闭弹窗不会禁用原有 2FA，可再次输入密码生成二维码。</p>
              </div>
            </div>
            <div className="flex justify-center rounded-xl border border-slate-200 bg-white p-5">
              <img src={enroll.qr} width={200} height={200} alt="TOTP 二维码" />
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-800/60 p-3">
              <div className="mb-1 text-[10px] font-semibold uppercase tracking-[.12em] text-slate-500">手动输入密钥</div>
              <code className="block break-all text-xs leading-5 text-cyan-300 select-all">{enroll.secret}</code>
            </div>
            <div className="border-t border-slate-800 pt-5">
              <div className="mb-3 flex items-start gap-3">
                <span className="grid h-7 w-7 shrink-0 place-items-center rounded-lg bg-cyan-500/10 font-mono text-xs text-cyan-300">02</span>
                <div>
                  <div className="text-sm font-medium text-slate-200">确认新验证码</div>
                  <p className="mt-1 text-xs leading-5 text-slate-500">输入验证器当前显示的 6 位验证码完成绑定。</p>
                </div>
              </div>
              <Field label="新验证码">
                <input
                  className="w-full text-center text-xl tracking-[0.5em]"
                  value={code}
                  onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  inputMode="numeric"
                  placeholder="······"
                  required
                />
              </Field>
              <Button onClick={verify} disabled={busy} className="w-full">确认绑定</Button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  )
}
