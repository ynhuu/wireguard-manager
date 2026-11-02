import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent } from 'react'
import { api, errorMessage } from '../api'
import type { VaultEntry } from '../api'
import { Alert, Button, Card, Field, Modal, PageTitle, Toast } from '../components/ui'

interface Generated {
  private_key: string
  public_key: string
  preshared_key?: string
}

interface KeyActionResult {
  error?: string
  config_error?: string
  config_note?: string
  apply_error?: string
  save_warning?: string
  file?: string
  applied?: boolean
}

interface KeyCreateResult {
  deploy?: KeyActionResult
}

interface KeyDeleteResult {
  config_removed?: boolean
  applied?: boolean
}

const emptyForm = {
  name: '',
  iface: '',
  public_key: '',
  private_key: '',
  preshared_key: '',
  address: '',
  dns: '',
  server_endpoint: '',
  allowed_ips: '',
  keepalive: '25',
  notes: '',
}

export default function KeyVault() {
  const [entries, setEntries] = useState<VaultEntry[]>([])
  const [confFiles, setConfFiles] = useState<string[]>([])
  const [defaultIface, setDefaultIface] = useState('')
  const [busyId, setBusyId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [msg, setMsg] = useState<{ kind: 'ok' | 'error'; text: string } | null>(null)
  const [modal, setModal] = useState<{ mode: 'create' } | { mode: 'edit'; entry: VaultEntry } | null>(null)
  const [qrFor, setQrFor] = useState<VaultEntry | null>(null)
  const [qrSrc, setQrSrc] = useState('')
  const [qrError, setQrError] = useState('')
  const loadRequest = useRef(0)

  useEffect(() => {
    let objectURL = ''
    let cancelled = false
    setQrSrc('')
    setQrError('')
    if (!qrFor) return

    api.getBlob(`/api/keys/${encodeURIComponent(qrFor.id)}/qrcode`)
      .then((blob) => {
        objectURL = URL.createObjectURL(blob)
        if (cancelled) {
          URL.revokeObjectURL(objectURL)
          return
        }
        setQrSrc(objectURL)
      })
      .catch((err: unknown) => {
        if (!cancelled) setQrError(errorMessage(err))
      })

    return () => {
      cancelled = true
      if (objectURL) URL.revokeObjectURL(objectURL)
    }
  }, [qrFor?.id])

  async function downloadConfig(e: VaultEntry) {
    try {
      const blob = await api.getBlob(`/api/keys/${encodeURIComponent(e.id)}/client-config`)
      const objectURL = URL.createObjectURL(blob)
      const link = document.createElement('a')
      const cleanedName = e.name.replace(/[^\p{L}\p{N}._-]/gu, '_')
      const filename = cleanedName && cleanedName !== '.' && cleanedName !== '..' ? cleanedName : 'wireguard-client'
      link.href = objectURL
      link.download = `${filename}.conf`
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(objectURL), 0)
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    }
  }

  async function load() {
    const request = ++loadRequest.current
    try {
      const r = await api.get<{ entries: VaultEntry[] }>('/api/keys')
      if (request !== loadRequest.current) return
      setEntries(r.entries ?? [])
      setError('')
    } catch (e: unknown) {
      if (request === loadRequest.current) setError(errorMessage(e))
    }
  }
  useEffect(() => {
    load()
    api.get<{ files: string[] }>('/api/conf/files').then((r) => {
      setConfFiles((r.files ?? []).map((f) => f.replace(/\.conf$/, '')))
    }).catch(() => {})
    api.get<{ default_iface?: string }>('/api/settings/defaults').then((d) => {
      setDefaultIface(d.default_iface || '')
    }).catch(() => {})
  }, [])

  async function toggleLoaded(e: VaultEntry) {
    const retry = e.pending_apply || e.needs_apply
    const action = retry ? '应用配置' : e.loaded ? '卸载' : '载入'
    if (!retry && e.loaded && !confirm(`卸载 ${e.name}？\n将从服务器配置中移除该 Peer 并立即应用，保留密钥库记录。`)) return
    setBusyId(e.id)
    try {
      const r = await api.post<KeyActionResult>(`/api/keys/${encodeURIComponent(e.id)}/${retry ? 'apply' : e.loaded ? 'unload' : 'deploy'}`, { apply_runtime: true })
      await load()
      const failure = r.error || r.config_error || r.config_note
      if (failure) {
        setMsg({ kind: 'error', text: `${action}失败：${failure}` })
      } else if (r.apply_error) {
        setMsg({ kind: 'error', text: `应用到 WG 失败：${r.apply_error}。点击「重试应用」只同步当前文件，不会反向载入/卸载。` })
      } else {
        setMsg({ kind: r.save_warning ? 'error' : 'ok', text: r.save_warning
          ? `${action}完成，但密钥库保存失败：${r.save_warning}`
          : `${action}完成并已同步 WG，密钥库记录已保留` })
      }
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusyId(null)
    }
  }

  async function deleteEntry(e: VaultEntry) {
    if (busyId !== null) return
    const target = e.iface ? `${e.iface}.conf` : '服务器配置文件'
    if (!confirm(`删除 ${e.name}？\n将同时从服务器 ${target} 移除该 Peer（自动备份）。`)) return
    setBusyId(e.id)
    try {
      const r = await api.del<KeyDeleteResult>(`/api/keys/${encodeURIComponent(e.id)}`)
      await load()
      if (r.config_removed) {
        let text = `已删除，${target} 中的 Peer 已移除`
        if (r.applied) text += ' 并已应用到运行中接口'
        setMsg({ kind: 'ok', text })
      } else if (r.config_removed === false) {
        setMsg({ kind: 'ok', text: '已删除密钥库记录（配置文件中未找到该 Peer）' })
      } else {
        setMsg({ kind: 'ok', text: '已删除密钥库记录' })
      }
    } catch (err: unknown) {
      setMsg({ kind: 'error', text: errorMessage(err) })
    } finally {
      setBusyId(null)
    }
  }

  // 按写入接口分组（空接口的条目归入默认接口），便于分块查看
  const groups = useMemo<[string, VaultEntry[]][]>(() => {
    const order: string[] = []
    const map: Record<string, VaultEntry[]> = {}
    for (const e of entries ?? []) {
      const key = e.iface || defaultIface || '默认'
      if (!map[key]) {
        map[key] = []
        order.push(key)
      }
      map[key].push(e)
    }
    return order.map((k) => [k, map[k]])
  }, [entries, defaultIface])

  return (
    <div>
      <PageTitle
        title="密钥库"
        desc="私钥 AES-256-GCM 加密存储、永不回显 · 客户端配置可下载或扫码导入"
        right={<Button onClick={() => setModal({ mode: 'create' })}>新增 Peer</Button>}
      />
      {error && <Toast kind="error">{error}</Toast>}
      {msg && <Toast kind={msg.kind}>{msg.text}</Toast>}

      {groups.length === 0 ? (
        <Card>
          <div className="px-4 py-8 text-center text-slate-500">
            暂无记录，点击右上角「新增 Peer」生成密钥对
          </div>
        </Card>
      ) : (
        groups.map(([iface, items]) => (
          <section key={iface} className="mb-8">
            <div className="mb-3 flex items-end justify-between">
              <div>
                <h2 className="font-mono text-sm font-semibold text-cyan-300">{iface}</h2>
                <p className="mt-1 text-xs text-slate-500">{items.length} 个客户端</p>
              </div>
              <span className="hidden font-mono text-[10px] uppercase tracking-wider text-slate-600 sm:block">密钥库 Peer</span>
            </div>
            <Card className="overflow-x-auto">
              <table className="peer-table w-full min-w-max text-sm">
              <thead>
                <tr className="text-left text-xs uppercase tracking-wider text-slate-500 border-b border-slate-800">
                  <th className="w-24 px-4 py-3">名称</th>
                  <th className="px-4 py-3">公钥</th>
                  <th className="px-4 py-3">地址</th>
                  <th className="px-4 py-3">操作</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={e.id} className="table-row border-b border-slate-800/60 last:border-0 align-top">
                    <td className="w-24 px-4 py-3 font-medium">
                      {e.name}
                      <div className="mt-1 text-xs text-slate-500">{e.pending_apply || e.needs_apply ? '待应用' : e.loaded ? '配置已载入' : '配置已卸载'}</div>
                    </td>
                    <td className="px-4 py-3 font-mono text-xs" title={e.public_key}>
                      {e.public_key}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs">{(e.address ?? []).join(', ') || '-'}</td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <button
                        className="text-xs text-slate-400 hover:text-slate-200 mr-3"
                        onClick={() => setQrFor(e)}
                        disabled={!e.has_private_key}
                      >
                        二维码
                      </button>
                      <button
                        className={`text-xs mr-3 ${
                          e.has_private_key ? 'text-cyan-400 hover:text-cyan-300' : 'cursor-not-allowed text-slate-600'
                        }`}
                        onClick={() => downloadConfig(e)}
                        disabled={!e.has_private_key}
                      >
                        下载
                      </button>
                      <button
                        className="text-xs text-emerald-400 hover:text-emerald-300 mr-3"
                        onClick={() => toggleLoaded(e)}
                        disabled={busyId !== null || !!e.config_error || (!!e.runtime_error && !e.pending_apply) || (!e.pending_apply && !e.needs_apply && !e.loaded && !e.address?.length)}
                        title={e.config_error || e.runtime_error || (e.pending_apply || e.needs_apply ? '只应用当前文件到 WG，不改变文件中的载入/卸载状态' : e.loaded ? '移除服务器 Peer 并立即应用，保留密钥库记录' : e.address?.length ? '写入服务器 Peer 并立即应用到 WG' : '请先设置客户端 Address')}
                      >
                        {busyId === e.id ? '处理中…' : e.pending_apply || e.needs_apply ? '重试应用' : e.loaded ? '卸载' : '载入'}
                      </button>
                      <button
                        className="text-xs text-cyan-400 hover:text-cyan-300 mr-3"
                        onClick={() => setModal({ mode: 'edit', entry: e })}
                        disabled={busyId !== null}
                      >
                        编辑
                      </button>
                      <button
                        className="text-xs text-red-400 hover:text-red-300"
                        onClick={() => void deleteEntry(e)}
                        disabled={busyId !== null}
                      >
                        {busyId === e.id ? '处理中…' : '删除'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
              </table>
            </Card>
          </section>
        ))
      )}

      <EntryModal
        confFiles={confFiles}
        open={!!modal}
        entry={modal?.mode === 'edit' ? modal.entry : null}
        onClose={() => setModal(null)}
        onSaved={(result) => {
          void load()
          if (modal?.mode === 'edit') {
            setMsg({ kind: 'ok', text: '已更新密钥库记录（已载入的客户端需卸载后重新载入，才能同步服务器配置）' })
            return
          }
          const d = result?.deploy
          if (d) {
            if (d.error) {
              setMsg({ kind: 'error', text: `已存入密钥库，但写入配置失败：${d.error}` })
            } else if (d.save_warning) {
              setMsg({ kind: 'error', text: `已写入 ${d.file}，但密钥库保存失败：${d.save_warning}` })
            } else {
              let t = `已存入密钥库并写入 ${d.file}`
              if (d.applied) t += '，已应用到运行中接口'
              else if (d.apply_error) t += `（应用失败：${d.apply_error}）`
              setMsg({ kind: 'ok', text: t })
            }
          } else if (result) {
            setMsg({ kind: 'ok', text: '已保存到密钥库' })
          }
        }}
      />
      <Modal open={!!qrFor} onClose={() => setQrFor(null)} title={`扫码导入 · ${qrFor?.name}`}>
        {qrFor && (
          <div>
            {qrError ? (
              <Alert kind="error">二维码加载失败：{qrError}</Alert>
            ) : qrSrc ? (
              <img className="mx-auto rounded bg-white p-2" src={qrSrc} alt="QR" width={280} height={280} />
            ) : (
              <div className="flex h-70 items-center justify-center text-sm text-slate-500">正在加载二维码…</div>
            )}
            <p className="mt-3 text-center text-xs text-slate-500">使用手机 WireGuard App 扫码即可导入隧道</p>
          </div>
        )}
      </Modal>
    </div>
  )
}

function EntryModal({
  confFiles,
  open,
  entry,
  onClose,
  onSaved,
}: {
  confFiles: string[]
  open: boolean
  entry: VaultEntry | null // null = 新建模式
  onClose: () => void
  onSaved: (result?: KeyCreateResult) => void
}) {
  const editing = !!entry
  const [form, setForm] = useState(emptyForm)
  const [clearPSK, setClearPSK] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [writeConf, setWriteConf] = useState(true)
  const [applyRuntime, setApplyRuntime] = useState(false)
  const [loadingIface, setLoadingIface] = useState(false)
  const [ifaceReady, setIfaceReady] = useState(false)
  const modalGeneration = useRef(0)
  const addressRequest = useRef(0)

  // 新建模式下，按所选接口重新计算客户端 Address / AllowedIPs；编辑模式只刷新 Endpoint。
  async function loadAddressFor(
    iface: string,
    refreshAddress = true,
    generation = modalGeneration.current,
  ) {
    if (!iface) {
      if (refreshAddress) setForm((f) => ({ ...f, address: '', allowed_ips: '', server_endpoint: '' }))
      setLoadingIface(false)
      setIfaceReady(false)
      return
    }
    const request = ++addressRequest.current
    setLoadingIface(true)
    setIfaceReady(false)
    try {
      const n = await api.get<{ address: string; server_subnets: string[]; server_endpoint?: string }>(
        `/api/keys/next-address?iface=${encodeURIComponent(iface)}`,
      )
      if (generation !== modalGeneration.current || request !== addressRequest.current) return
      setForm((f) => {
        if (f.iface !== iface) return f
        return {
          ...f,
          ...(refreshAddress
            ? {
                address: n.address || '',
                allowed_ips: (n.server_subnets ?? []).join(', '),
              }
            : {}),
          server_endpoint: n.server_endpoint || '',
        }
      })
      setError('')
      setIfaceReady(true)
    } catch (e: unknown) {
      if (generation === modalGeneration.current && request === addressRequest.current) {
        setError(errorMessage(e))
        setIfaceReady(false)
      }
    } finally {
      if (generation === modalGeneration.current && request === addressRequest.current) {
        setLoadingIface(false)
      }
    }
  }

  useEffect(() => {
    const generation = ++modalGeneration.current
    ++addressRequest.current
    setLoadingIface(false)
    setIfaceReady(false)
    const cancel = () => {
      if (modalGeneration.current === generation) ++modalGeneration.current
      ++addressRequest.current
    }
    if (!open) return cancel

    setError('')
    setBusy(false)
    setClearPSK(false)
    setWriteConf(true)
    setApplyRuntime(false)
    if (entry) {
      // 编辑模式：预填现有值；私钥/PSK 永不回显，留空表示保持不变
      setForm({
        name: entry.name,
        iface: entry.iface || '',
        public_key: entry.public_key,
        private_key: '',
        preshared_key: '',
        address: (entry.address ?? []).join(', '),
        dns: (entry.dns ?? []).join(', '),
        server_endpoint: entry.server_endpoint || '',
        allowed_ips: (entry.allowed_ips ?? []).join(', '),
        keepalive: String(entry.keepalive || 0),
        notes: entry.notes || '',
      })
      setIfaceReady(true)
      return cancel
    }

    // 新建模式：接口必须存在于配置文件列表；Address、AllowedIPs 和 Endpoint 均按接口加载。
    const initialize = async () => {
      setLoadingIface(true)
      try {
        const d = await api.get<{ server_endpoint: string; default_iface?: string }>('/api/settings/defaults')
        if (generation !== modalGeneration.current) return
        const ifaces = confFiles ?? []
        const configuredDefault = d.default_iface || ''
        const target = configuredDefault && ifaces.includes(configuredDefault) ? configuredDefault : ifaces[0] || ''
        setForm({ ...emptyForm, iface: target })
        if (!target) {
          setLoadingIface(false)
          setIfaceReady(false)
          return
        }
        await loadAddressFor(target, true, generation)
      } catch (err: unknown) {
        if (generation === modalGeneration.current) {
          setError(`加载默认值失败：${errorMessage(err)}`)
          setLoadingIface(false)
          setIfaceReady(false)
        }
      }
    }
    void initialize()
    return cancel
  }, [open, entry, confFiles])

  const set = (k: keyof typeof emptyForm) => (ev: ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) =>
    setForm((f) => ({ ...f, [k]: ev.target.value }))

  async function generateKeypair() {
    try {
      const g = await api.post<Generated>('/api/keys/generate', {})
      setForm((f) => ({ ...f, public_key: g.public_key, private_key: g.private_key }))
    } catch (e: unknown) {
      setError(errorMessage(e))
    }
  }

  async function generatePSK() {
    setClearPSK(false)
    try {
      const g = await api.post<Generated>('/api/keys/generate', { with_preshared_key: true })
      if (g.preshared_key) setForm((f) => ({ ...f, preshared_key: g.preshared_key! }))
    } catch (e: unknown) {
      setError(errorMessage(e))
    }
  }

  async function submit(ev: FormEvent) {
    ev.preventDefault()
    if (loadingIface || !ifaceReady) return
    setError('')
    setBusy(true)
    const csv = (v: string): string[] => v.split(',').map((s) => s.trim()).filter(Boolean)
    const base = {
      name: form.name,
      iface: form.iface || undefined,
      public_key: form.public_key,
      private_key: form.private_key || undefined,
      preshared_key: form.preshared_key || undefined,
      address: form.address ? csv(form.address) : undefined,
      dns: form.dns ? csv(form.dns) : undefined,
      server_endpoint: form.server_endpoint || undefined,
      allowed_ips: form.allowed_ips ? csv(form.allowed_ips) : undefined,
    }
    try {
      let result
      if (entry) {
        await api.put<KeyActionResult>(`/api/keys/${encodeURIComponent(entry.id)}`, {
          ...base,
          preshared_key: clearPSK ? '' : form.preshared_key || undefined,
          address: csv(form.address),
          dns: csv(form.dns),
          server_endpoint: form.server_endpoint,
          allowed_ips: csv(form.allowed_ips),
          keepalive: form.keepalive === '' ? undefined : parseInt(form.keepalive, 10),
          notes: form.notes,
        })
      } else {
        result = await api.post<KeyCreateResult>('/api/keys', {
          ...base,
          keepalive: parseInt(form.keepalive, 10) || 0,
          notes: form.notes || undefined,
          deploy_to_config: writeConf ? { apply_runtime: applyRuntime } : undefined,
        })
      }
      onClose()
      onSaved(result)
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal open={open} onClose={onClose} title={editing ? `编辑 Peer · ${entry?.name}` : '新增 Peer'} wide>
      {error && <Alert kind="error">{error}</Alert>}
      {!editing && (
        <Button variant="ghost" onClick={generateKeypair}>
          ⚡ 生成新密钥对
        </Button>
      )}
      <form onSubmit={submit} className={`grid grid-cols-1 gap-x-4 sm:grid-cols-2 ${editing ? '' : 'mt-4'}`}>
        <Field label="写入的接口">
          <select
            className="w-full"
            value={form.iface}
            disabled={editing && !!(entry?.loaded || entry?.runtime_loaded || entry?.pending_apply)}
            title={editing && (entry?.loaded || entry?.runtime_loaded || entry?.pending_apply) ? '请先卸载并成功应用，再更换接口' : undefined}
            onChange={(ev) => {
              const v = ev.target.value
              ++addressRequest.current
              setError('')
              setIfaceReady(false)
              setForm((f) => ({
                ...f,
                iface: v,
                server_endpoint: '',
                ...(!editing ? { address: '', allowed_ips: '' } : {}),
              }))
              if (v) void loadAddressFor(v, !editing)
              else {
                setLoadingIface(false)
                setIfaceReady(false)
              }
            }}
          >
            {(confFiles ?? []).length === 0 && <option value="">（暂无配置文件）</option>}
            {(confFiles ?? []).map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </Field>
        <div className="hidden sm:block" />
        <Field label="名称 *">
          <input className="w-full" value={form.name} onChange={set('name')} required placeholder="my-phone" />
        </Field>
        <Field label="服务端 Endpoint（写入客户端配置）">
          <input className="w-full" value={form.server_endpoint} onChange={set('server_endpoint')} placeholder="vpn.example.com:51820" />
        </Field>
        {!editing && (
          <div className="sm:col-span-2">
            <Field label="客户端私钥 *">
              <input
                className="w-full font-mono text-xs"
                value={form.private_key}
                onChange={set('private_key')}
                required
              />
            </Field>
          </div>
        )}
        {!editing && (
          <div className="sm:col-span-2">
            <Field label="客户端公钥 *">
              <input
                className="w-full font-mono text-xs"
                value={form.public_key}
                onChange={set('public_key')}
                required
              />
            </Field>
          </div>
        )}
        <div className="sm:col-span-2">
          <Field label="PresharedKey（可选）">
            <div className="flex gap-2 items-center">
              <input
                className="flex-1 font-mono text-xs"
                type="text"
                disabled={clearPSK}
                value={form.preshared_key}
                onChange={set('preshared_key')}
                placeholder={
                  editing
                    ? entry?.has_preshared_key
                      ? '已设置，留空保持不变'
                      : '默认不使用'
                    : '默认不使用'
                }
              />
              {form.preshared_key && (
                <button
                  type="button"
                  className="text-xs text-slate-400 hover:text-slate-200 shrink-0"
                  onClick={() => setForm((f) => ({ ...f, preshared_key: '' }))}
                >
                  清除
                </button>
              )}
              <button
                type="button"
                className="text-xs text-cyan-400 hover:text-cyan-300 shrink-0"
                onClick={generatePSK}
              >
                生成
              </button>
            </div>
          </Field>
          {editing && entry?.has_preshared_key && (
            <label className="flex items-center gap-2 text-sm text-slate-400">
              <input type="checkbox" checked={clearPSK} onChange={(e) => setClearPSK(e.target.checked)} />
              移除已保存的 PSK（重新载入后同步服务器）
            </label>
          )}
        </div>
        <Field label="客户端 Address">
          <input className="w-full" value={form.address} onChange={set('address')} placeholder="10.10.0.2/32" />
        </Field>
        <Field label="客户端 DNS">
          <input className="w-full" value={form.dns} onChange={set('dns')} placeholder="1.1.1.1" />
        </Field>
        <Field label="客户端 AllowedIPs">
          <input className="w-full" value={form.allowed_ips} onChange={set('allowed_ips')} placeholder="如 10.10.0.0/24" />
        </Field>
        <Field label="PersistentKeepalive（秒）">
          <input
            className="w-full"
            value={form.keepalive}
            onChange={(e) => setForm((f) => ({ ...f, keepalive: e.target.value.replace(/\D/g, '') }))}
          />
        </Field>
        {!editing && (
          <div className="sm:col-span-2 border-t border-slate-800 pt-4 mb-2 space-y-2">
            <label className="flex items-center gap-2 text-sm text-slate-300">
              <input type="checkbox" checked={writeConf} onChange={(e) => setWriteConf(e.target.checked)} className="accent-cyan-500" />
              同时写入服务器 wg0.conf（以客户端 Address 作为服务端 AllowedIPs）
            </label>
            <label className={`flex items-center gap-2 text-sm ${writeConf ? 'text-slate-300' : 'text-slate-600'}`}>
              <input
                type="checkbox"
                checked={applyRuntime}
                disabled={!writeConf}
                onChange={(e) => setApplyRuntime(e.target.checked)}
                className="accent-cyan-500"
              />
              写入后立即应用到运行中接口
            </label>
          </div>
        )}
        <div className={`sm:col-span-2 flex justify-end gap-2 ${editing ? 'mt-4' : ''}`}>
          <Button variant="ghost" onClick={onClose}>
            取消
          </Button>
          <Button type="submit" disabled={busy || loadingIface || !ifaceReady}>
            {editing ? '保存修改' : writeConf ? '保存并写入配置' : '保存到密钥库'}
          </Button>
        </div>
      </form>
    </Modal>
  )
}
