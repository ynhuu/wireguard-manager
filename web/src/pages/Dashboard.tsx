import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errorMessage, fmtBytes, shortKey } from '../api'
import type { InterfaceStatus } from '../api'
import { Alert, Badge, Button, Card, PageTitle, Toast } from '../components/ui'

export function useStatus(intervalMs = 5000) {
  const [ifaces, setIfaces] = useState<InterfaceStatus[]>([])
  const [demo, setDemo] = useState(false)
  const [error, setError] = useState('')
  const refreshing = useRef(false)

  const refresh = useCallback(async () => {
    if (refreshing.current || document.visibilityState === 'hidden') return
    refreshing.current = true
    try {
      const r = await api.get<{ demo: boolean; interfaces: InterfaceStatus[] }>('/api/status')
      setIfaces(r.interfaces ?? [])
      setDemo(r.demo)
      setError('')
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      refreshing.current = false
    }
  }, [])

  useEffect(() => {
    refresh()
    if (!intervalMs) return
    const t = setInterval(refresh, intervalMs)
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') void refresh()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => {
      clearInterval(t)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [refresh, intervalMs])

  return { ifaces, demo, error, refresh }
}

const actionLabel: Record<'up' | 'down' | 'restart', string> = {
  up: '启动',
  down: '停止',
  restart: '重启',
}

export default function Dashboard() {
  const { ifaces, demo, error, refresh } = useStatus()
  const [confFiles, setConfFiles] = useState<string[]>([])
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [busyAction, setBusyAction] = useState<string | null>(null)

  // 首次挂载及运行集合变化（启动/停止后）刷新配置文件列表
  const runningKey = ifaces.map((i) => i.name).join(',')
  useEffect(() => {
    api
      .get<{ files: string[] }>('/api/conf/files')
      .then((r) => setConfFiles(r.files ?? []))
      .catch(() => {
        /* 权限等问题时静默，总览仍可显示运行中的接口 */
      })
  }, [runningKey])

  async function quick(iface: string, action: 'up' | 'down' | 'restart') {
    const actionKey = `${iface}:${action}`
    if (busyAction !== null) return
    setBusyAction(actionKey)
    setMsg(null)
    try {
      await api.post('/api/wg/quick', { iface, action })
      setMsg({ kind: 'ok', text: `${iface} 已${actionLabel[action]}` })
    } catch (e: unknown) {
      // restart 是 down→up 两步：up 失败时接口多半已停，提示用户可手动拉起
      const hint = action === 'restart' ? '（接口可能已停止，可在下方「启动接口」重新拉起）' : ''
      setMsg({ kind: 'error', text: `${iface} ${actionLabel[action]}失败：${errorMessage(e)}${hint}` })
    } finally {
      setBusyAction(null)
      await refresh()
    }
  }

  const runningNames = new Set(ifaces.map((i) => i.name))
  const stopped = confFiles.map((f) => f.replace(/\.conf$/, '')).filter((n) => n && !runningNames.has(n))

  return (
    <div>
      <PageTitle
        title="总览"
        desc="接口实时状态 · 每 5 秒自动刷新"
        right={
          <>
            <span className="hidden items-center gap-2 text-xs text-slate-500 sm:flex"><span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />实时同步</span>
            {demo && <span className="rounded-lg border border-amber-800 bg-amber-900/40 px-2.5 py-1.5 text-xs font-semibold text-amber-400">演示模式</span>}
          </>
        }
      />
      {error && <Toast kind="error">{error}</Toast>}
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}
      {ifaces.length === 0 && stopped.length === 0 && !error && (
        <Alert kind="info">没有 WireGuard 接口。到「配置文件」页点击「＋ 新建配置」创建第一个接口。</Alert>
      )}
      <div className="mb-6 grid gap-3 sm:grid-cols-3">
        {[
          ['接口', ifaces.length, '活跃隧道'],
          ['Peers', ifaces.reduce((total, iface) => total + (iface.peers ?? []).length, 0), '已知客户端'],
          ['在线', ifaces.reduce((total, iface) => total + (iface.peers ?? []).filter((peer) => peer.latest_handshake_ago_seconds > 0 && peer.latest_handshake_ago_seconds < 180).length, 0), '最近 3 分钟'],
        ].map(([label, value, detail]) => (
          <div key={label} className="metric-card surface-card rounded-2xl p-4 sm:p-5">
            <div className="relative z-10 flex items-end justify-between"><div><div className="text-xs font-semibold uppercase tracking-[.14em] text-slate-500">{label}</div><div className="mt-2 text-3xl font-bold tracking-tight text-slate-100">{value}</div></div><span className="text-[10px] text-slate-500">{detail}</span></div>
          </div>
        ))}
      </div>
      <div className="mb-4 flex items-center justify-between"><div><h2 className="text-base font-semibold text-slate-100">接口</h2><p className="mt-1 text-xs text-slate-500">运行中的 WireGuard 隧道</p></div><span className="font-mono text-xs text-slate-600">{String(ifaces.length + stopped.length).padStart(2, '0')} 个接口</span></div>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
        {ifaces.map((i) => {
          const peers = i.peers ?? []
          const rx = peers.reduce((a, p) => a + p.rx_bytes, 0)
          const tx = peers.reduce((a, p) => a + p.tx_bytes, 0)
          const online = peers.filter(
            (p) => p.latest_handshake_ago_seconds > 0 && p.latest_handshake_ago_seconds < 180,
          ).length
          return (
            <Card key={i.name} className="p-5">
              <div className="mb-5 flex items-start justify-between">
                <div><div className="mb-1 flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_0_4px_color-mix(in_srgb,var(--success)_12%,transparent)]" /><span className="font-mono font-semibold text-cyan-300">{i.name}</span></div><span className="text-xs text-slate-500">WireGuard 接口</span></div>
                <span className="rounded-lg bg-slate-800/60 px-2 py-1 font-mono text-xs text-slate-400">{i.listen_port > 0 ? `:${i.listen_port}` : 'offline'}</span>
              </div>
              <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
                <dt className="text-slate-500">公钥</dt>
                <dd className="font-mono text-xs text-right truncate" title={i.public_key}>
                  {shortKey(i.public_key || '-')}
                </dd>
                <dt className="text-slate-500">Peers</dt>
                <dd className="text-right">{peers.length}</dd>
                <dt className="text-slate-500">在线</dt>
                <dd className="text-right text-emerald-400">{online}</dd>
                <dt className="text-slate-500">接收 ↓</dt>
                <dd className="text-right">{fmtBytes(rx)}</dd>
                <dt className="text-slate-500">发送 ↑</dt>
                <dd className="text-right">{fmtBytes(tx)}</dd>
              </dl>
              <div className="mt-5 flex justify-end gap-2 border-t border-slate-800 pt-4">
                <Button variant="danger" onClick={() => void quick(i.name, 'down')} disabled={busyAction !== null}>
                  {busyAction === `${i.name}:down` ? '处理中…' : '停止接口'}
                </Button>
                <Button variant="ghost" onClick={() => void quick(i.name, 'restart')} disabled={busyAction !== null}>
                  {busyAction === `${i.name}:restart` ? '处理中…' : '重启'}
                </Button>
              </div>
            </Card>
          )
        })}

        {/* 已有配置但未运行的接口 */}
        {stopped.map((name) => (
          <Card key={name} className="border-dashed border-slate-700 p-5">
            <div className="mb-5 flex items-center justify-between">
              <div><span className="font-mono font-semibold text-slate-400">{name}</span><div className="mt-1 text-xs text-slate-600">WireGuard 接口</div></div>
              <Badge online={false} />
            </div>
            <p className="text-sm text-slate-500 leading-6">
              配置文件存在，接口未运行。
              <br />
              启动失败时请检查「配置文件」页的语法与网卡名。
            </p>
            <div className="mt-4 flex justify-end border-t border-slate-800 pt-4">
              <Button onClick={() => void quick(name, 'up')} disabled={busyAction !== null}>
                {busyAction === `${name}:up` ? '处理中…' : '启动接口'}
              </Button>
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}
