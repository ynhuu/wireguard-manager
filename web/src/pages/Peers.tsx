import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errorMessage, fmtAgo, fmtBytes, shortKey } from '../api'
import type { VaultEntry } from '../api'
import { Badge, Button, Card, PageTitle, Toast } from '../components/ui'
import { useStatus } from './Dashboard'

export default function Peers() {
  const { ifaces, demo, error, refresh } = useStatus()
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [vaultNames, setVaultNames] = useState<Record<string, string>>({})
  const [removingPeer, setRemovingPeer] = useState<string | null>(null)
  const vaultRequest = useRef(0)

  // 密钥库条目只在用户编辑时变化，挂载时拉一次即可；
  // 「刷新」按钮会同时重新拉取（依赖 useStatus 的轮询会导致每 5s 重复请求）。
  const loadVaultNames = useCallback(() => {
    const request = ++vaultRequest.current
    api
      .get<{ entries: Pick<VaultEntry, 'public_key' | 'name'>[] }>('/api/keys')
      .then((d) => {
        if (request !== vaultRequest.current) return
        const m: Record<string, string> = {}
        for (const e of d?.entries ?? []) m[e.public_key] = e.name
        setVaultNames(m)
      })
      .catch(() => {})
  }, [])

  useEffect(() => {
    loadVaultNames()
  }, [loadVaultNames])

  function refreshAll() {
    loadVaultNames()
    refresh()
  }

  async function removePeer(iface: string, publicKey: string) {
    const requestKey = `${iface}:${publicKey}`
    if (removingPeer !== null || !confirm('确定从运行中的接口移除该 peer？')) return
    setRemovingPeer(requestKey)
    try {
      await api.post('/api/wg/set/peer', { iface, public_key: publicKey, remove: true })
      setMsg({ kind: 'ok', text: '已从接口移除该 peer' })
      await refresh()
    } catch (error: unknown) {
      setMsg({ kind: 'error', text: `移除失败：${errorMessage(error)}` })
    } finally {
      setRemovingPeer(null)
    }
  }

  return (
    <div>
      <PageTitle
        title="Peers"
        desc="Peer 实时状态 · 握手 3 分钟内视为在线"
        right={
          <>
            {demo && (
              <span className="mr-2 text-xs px-2 py-1 rounded bg-amber-900/40 text-amber-400 border border-amber-800">
                DEMO 模式
              </span>
            )}
            <Button variant="ghost" onClick={refreshAll}>
              刷新
            </Button>
          </>
        }
      />
      {error && <Toast kind="error">{error}</Toast>}
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}

      {ifaces.map((i) => (
        <section key={i.name} className="mb-8">
          <div className="mb-3 flex items-end justify-between">
            <div><h2 className="font-mono text-sm font-semibold text-cyan-300">{i.name}</h2><p className="mt-1 text-xs text-slate-500">{(i.peers ?? []).length} 个客户端</p></div>
            <span className="hidden font-mono text-[10px] uppercase tracking-wider text-slate-600 sm:block">运行中 Peer</span>
          </div>
          <Card className="overflow-x-auto">
            <table className="peer-table w-full min-w-max text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                  <th className="px-4 py-3">状态</th>
                  <th className="w-24 px-4 py-3">名称</th>
                  <th className="px-4 py-3">公钥</th>
                  <th className="px-4 py-3">端点</th>
                  <th className="px-4 py-3">允许的 IP</th>
                  <th className="px-4 py-3">最近握手</th>
                  <th className="px-4 py-3 text-right">接收 ↓</th>
                  <th className="px-4 py-3 text-right">发送 ↑</th>
                  <th className="px-4 py-3" />
                </tr>
              </thead>
              <tbody>
                {(i.peers ?? []).length === 0 && (
                  <tr>
                    <td colSpan={9} className="px-4 py-6 text-center text-slate-500">
                      无 peer
                    </td>
                  </tr>
                )}
                {(i.peers ?? []).map((p) => {
                  const online =
                    p.latest_handshake_ago_seconds > 0 && p.latest_handshake_ago_seconds < 180
                  return (
                    <tr key={p.public_key} className="table-row border-b border-slate-800/60 last:border-0">
                      <td className="px-4 py-3">
                        <Badge online={online} />
                      </td>
                      <td className="w-24 px-4 py-3 text-xs" title={vaultNames[p.public_key] || ''}>
                        {vaultNames[p.public_key] ? (
                          <span className="text-cyan-300">{vaultNames[p.public_key]}</span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs" title={p.public_key}>
                        {shortKey(p.public_key)}
                        {p.preshared_key_set && <span title="已设置 PSK"> 🔒</span>}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">{p.endpoint || '-'}</td>
                      <td className="max-w-35 truncate px-4 py-3 font-mono text-xs" title={(p.allowed_ips ?? []).join(', ')}>
                        {(p.allowed_ips ?? []).join(', ') || '-'}
                      </td>
                      <td className="px-4 py-3">{fmtAgo(p.latest_handshake_ago_seconds)}</td>
                      <td className="px-4 py-3 text-right">{fmtBytes(p.rx_bytes)}</td>
                      <td className="px-4 py-3 text-right">{fmtBytes(p.tx_bytes)}</td>
                      <td className="px-4 py-3 text-right whitespace-nowrap">
                        <button
                          className="text-xs text-red-400 hover:text-red-300"
                          onClick={() => void removePeer(i.name, p.public_key)}
                          disabled={removingPeer !== null}
                        >
                          {removingPeer === `${i.name}:${p.public_key}` ? '处理中…' : '移除'}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </Card>
        </section>
      ))}
    </div>
  )
}
