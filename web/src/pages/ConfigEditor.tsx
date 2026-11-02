import { useCallback, useEffect, useRef, useState } from 'react'
import { api, errorData, errorMessage } from '../api'
import { Alert, Button, Card, Field, Modal, PageTitle, Toast } from '../components/ui'

interface ParsedConf {
  interface: {
    private_key: string
    listen_port: number
    address: string[]
    dns: string[]
    mtu: number
  }
  peers: { public_key: string; preshared_key: string; allowed_ips: string[]; endpoint: string; persistent_keepalive: number }[]
}

interface ConfigReadResponse {
  file: string
  content: string
  parsed: ParsedConf | null
  parse_error?: string
  revision: string
}

export default function ConfigEditor() {
  const [files, setFiles] = useState<string[]>([])
  const [confDir, setConfDir] = useState('')
  const [file, setFile] = useState('')
  const [content, setContent] = useState('')
  const [parsed, setParsed] = useState<ParsedConf | null>(null)
  const [parseError, setParseError] = useState('')
  const [dirty, setDirty] = useState(false)
  const [error, setError] = useState('')
  const [okMsg, setOkMsg] = useState('')
  const editorRef = useRef<HTMLTextAreaElement>(null)
  const [creating, setCreating] = useState(false)
  const [newName, setNewName] = useState('wg0')
  const [newPort, setNewPort] = useState('51820')
  const [newAddr, setNewAddr] = useState('10.18.0.1/24')
  const [createErr, setCreateErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [loading, setLoading] = useState(false)
  const [loadedFile, setLoadedFile] = useState('')
  const [revision, setRevision] = useState('')
  const [readVersion, setReadVersion] = useState(0)
  const readRequest = useRef(0)

  // 从 CIDR 计算 IPv4 网络地址（如 10.18.0.1/24 → 10.18.0.0/24）；非 IPv4 返回空
  function subnetOf(cidr: string): string {
    const [ip, bitsStr] = cidr.trim().split('/')
    if (!ip || !bitsStr || ip.includes(':')) return ''
    const bits = parseInt(bitsStr, 10)
    const o = ip.split('.').map(Number)
    if (o.length !== 4 || o.some((n) => isNaN(n) || n < 0 || n > 255)) return ''
    if (isNaN(bits) || bits < 8 || bits > 32) return ''
    let v = (((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0)
    if (bits < 32) v = (v & (0xffffffff << (32 - bits))) >>> 0
    return `${[v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.')}/${bits}`
  }
  const [autoUpEnabled, setAutoUpEnabled] = useState(true)
  const [autoUpBusy, setAutoUpBusy] = useState(false)

  useEffect(() => {
    if (!file) return
    api.get<{ enabled: boolean }>(`/api/conf/auto-up?file=${encodeURIComponent(file)}`)
      .then((r) => setAutoUpEnabled(r.enabled))
      .catch(() => setAutoUpEnabled(true))
  }, [file])

  async function toggleAutoUp(enabled: boolean) {
    if (autoUpBusy || !file) return
    setAutoUpEnabled(enabled)
    setAutoUpBusy(true)
    try {
      await api.post('/api/conf/auto-up', { file, enabled })
    } catch (e: unknown) {
      setAutoUpEnabled(!enabled)
      setError(errorMessage(e))
    } finally {
      setAutoUpBusy(false)
    }
  }

  function openCreate() {
    let max = -1
    for (const f of files ?? []) {
      const m = f.replace(/\.conf$/, '').match(/^wg(\d+)$/)
      if (m) max = Math.max(max, parseInt(m[1], 10))
    }
    setNewName(`wg${max + 1}`)
    setNewPort('51820')
    setNewAddr('10.18.0.1/24')
    setCreateErr('')
    setCreating(true)
  }

  async function createNow() {
    const name = newName.trim().replace(/\.conf$/, '')
    if (!/^[a-zA-Z0-9_-]{1,15}$/.test(name)) {
      setCreateErr('接口名只能包含字母/数字/_/-，最长 15 字符')
      return
    }
    if ((files ?? []).some((f) => f.replace(/\.conf$/, '') === name)) {
      setCreateErr(`${name}.conf 已存在`)
      return
    }
    setCreateErr('')
    setBusy(true)
    try {
      const port = parseInt(newPort, 10)
      if (isNaN(port) || port < 1 || port > 65535) {
        setCreateErr('监听端口必须是 1-65535 的数字')
        return
      }
      const { private_key } = await api.post<{ private_key: string }>('/api/keys/generate', {})
      const subnet = subnetOf(newAddr)
      let tpl =
        `[Interface]\n` +
        `PrivateKey = ${private_key}\n` +
        `ListenPort = ${port}\n` +
        `Address = ${newAddr.trim()}\n`
      if (subnet) {
        tpl +=
          `PostUp = iptables -t nat -A POSTROUTING -s ${subnet} -o eth0 -j MASQUERADE\n` +
          `PostDown = iptables -t nat -D POSTROUTING -s ${subnet} -o eth0 -j MASQUERADE\n`
      }
      // 不写 SaveConfig：它会让 wg-quick down 把运行态（含 roaming 学习到的
      // 客户端 Endpoint）经 wg showconf 回写进配置文件，污染持久化内容
      await api.put('/api/conf/write', { file: name + '.conf', content: tpl, create: true })
      setOkMsg(`已创建并保存 ${name}.conf（服务端私钥已自动生成）`)
      setError('')
      setCreating(false)
      await loadFiles()
      setFile(name + '.conf')
      setContent(tpl)
      setDirty(false)
    } catch (e: unknown) {
      const parseError = errorData(e)?.parse_error
      setCreateErr(parseError ? `校验失败：${parseError}` : errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  // 编辑器高度跟随内容，避免出现内部滚动条
  useEffect(() => {
    const el = editorRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = `${el.scrollHeight + 2}px`
  }, [content])

  const loadFiles = useCallback(async () => {
    const r = await api.get<{ files: string[]; conf_dir: string }>('/api/conf/files')
    setFiles(r.files ?? [])
    setConfDir(r.conf_dir)
    if ((r.files ?? []).length) setFile((current) => current || r.files[0])
  }, [])

  useEffect(() => {
    loadFiles().catch((e: unknown) => setError(errorMessage(e)))
  }, [])

  useEffect(() => {
    if (!file) return
    const request = ++readRequest.current
    let cancelled = false
    setLoading(true)
    setLoadedFile('')
    setContent('')
    setParsed(null)
    setParseError('')
    api
      .get<ConfigReadResponse>(`/api/conf/read?file=${encodeURIComponent(file)}`)
      .then((r) => {
        if (cancelled || request !== readRequest.current) return
        setContent(r.content)
        setRevision(r.revision)
        setLoadedFile(file)
        setParsed(r.parsed ?? null)
        setParseError(r.parse_error ?? '')
        setDirty(false)
        setError('')
        setOkMsg('')
      })
      .catch((e) => {
        if (!cancelled && request === readRequest.current) setError(`读取 ${file} 失败：${errorMessage(e)}`)
      })
      .finally(() => {
        if (!cancelled && request === readRequest.current) setLoading(false)
      })
    return () => { cancelled = true }
  }, [file, readVersion])

  async function save() {
    if (busy || loading || loadedFile !== file) return
    setError('')
    setOkMsg('')
    setBusy(true)
    try {
      await api.put('/api/conf/write', { file, content, revision })
      setOkMsg(`已保存 ${file}（自动备份旧文件）`)
      setDirty(false)
      await loadFiles()
      const rd = await api.get<ConfigReadResponse>(`/api/conf/read?file=${encodeURIComponent(file)}`)
      setContent(rd.content)
      setRevision(rd.revision)
      setParsed(rd.parsed ?? null)
      setParseError(rd.parse_error ?? '')
    } catch (e: unknown) {
      const parseError = errorData(e)?.parse_error
      setError(parseError ? `语法校验失败：${parseError}` : errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  async function removeConf() {
    if (!file || busy || loading) return
    if (
      !confirm(
        `删除 ${file}？\n若该接口正在运行将先自动停止；\n配置文件及其所有备份将被彻底删除，无法恢复。`,
      )
    )
      return
    setError('')
    setOkMsg('')
    setBusy(true)
    try {
      const r = await api.del<{ removed_backups: number; stopped?: boolean }>(
        `/api/conf/delete?file=${encodeURIComponent(file)}`,
      )
      const remaining = (files ?? []).filter((f) => f !== file)
      const next = remaining[0] ?? ''
      setOkMsg(
        `已删除 ${file}` +
          (r.stopped ? '，接口已停止' : '') +
          (r.removed_backups ? `（含 ${r.removed_backups} 个备份）` : ''),
      )
      setFile(next)
      if (!next) {
        setContent('')
        setParsed(null)
        setParseError('')
        setDirty(false)
      }
      await loadFiles()
    } catch (e: unknown) {
      setError(errorMessage(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div>
      <PageTitle
        title="配置文件"
        desc={`${confDir} · 保存前自动校验语法并备份原文件`}
        right={
          <div className="config-page-actions flex w-full flex-col gap-2 sm:w-auto sm:flex-row sm:flex-wrap sm:items-center sm:gap-3 lg:w-full lg:flex-col lg:items-end xl:w-auto">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3">
              <label
                className="flex shrink-0 items-center gap-1.5 whitespace-nowrap text-sm text-slate-400"
              title="程序启动时自动开启此接口（全局开关在「设置」页）"
              >
                <input
                  type="checkbox"
                  checked={file ? autoUpEnabled : false}
                  onChange={(e) => toggleAutoUp(e.target.checked)}
                  disabled={!file || autoUpBusy}
                  className="accent-cyan-500"
                />
                随程序自启
              </label>
            </div>
            <div className="grid grid-cols-2 gap-2 sm:flex sm:items-center sm:gap-3">
              <Button variant="ghost" onClick={openCreate} disabled={busy || loading} className="w-full whitespace-nowrap px-2 sm:w-auto sm:px-4">
                ＋ 新建配置
              </Button>
              <Button variant="ghost" disabled={!file || busy || loading} onClick={() => {
                if (dirty && !confirm('重新读取会丢弃当前未保存的修改，继续？')) return
                ++readRequest.current
                setLoadedFile('')
                setReadVersion((v) => v + 1)
              }} className="w-full whitespace-nowrap px-2 sm:w-auto sm:px-4">重新读取</Button>
              <Button variant="danger" onClick={removeConf} disabled={!file || busy || loading} className="w-full whitespace-nowrap px-2 sm:w-auto sm:px-4">
                删除配置
              </Button>
              <Button onClick={save} disabled={!file || busy || loading || loadedFile !== file} className="w-full whitespace-nowrap px-2 sm:w-auto sm:px-4">
                保存
              </Button>
            </div>
          </div>
        }
      />
      {error && <Toast kind="error">{error}</Toast>}
      {okMsg && <Toast kind="ok">{okMsg}</Toast>}
      {parseError && !error && <Toast kind="error">语法校验失败：{parseError}</Toast>}

      <div className="flex gap-2 mb-4 flex-wrap">
        {(files ?? []).map((f) => (
          <button
            key={f}
            disabled={busy}
            onClick={() => {
              if (f !== file && dirty && !confirm(`${file} 有未保存的修改，切换将丢弃，确定？`)) return
              if (f !== file) {
                ++readRequest.current
                setLoadedFile('')
              }
              setFile(f)
            }}
            className={`px-3 py-1.5 text-sm rounded border font-mono ${
              f === file
                ? 'border-cyan-500 text-cyan-300 bg-cyan-500/10'
                : 'border-slate-800 text-slate-400 hover:border-slate-600'
            }`}
          >
            {f}
            {f === file && dirty ? ' *' : ''}
          </button>
        ))}
        {files.length === 0 && (
          <span className="text-sm text-slate-500">
            目录下暂无配置文件，点击右上角「＋ 新建配置」创建第一个接口（如 wg0）
          </span>
        )}
      </div>

      <div className="grid min-w-0 gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <Card className="code-panel min-w-0 overflow-hidden p-4">
          <textarea
            ref={editorRef}
            className="w-full min-w-0 max-w-full min-h-75 overflow-x-auto no-scrollbar bg-transparent font-mono text-xs leading-5"
            spellCheck={false}
            wrap="off"
            value={content}
            disabled={busy || loading || loadedFile !== file}
            onChange={(e) => {
              setContent(e.target.value)
              setDirty(true)
            }}
          />
        </Card>

        <Card className="hidden h-fit p-5 md:block">
          <div className="eyebrow mb-2">配置解析</div>
          <h3 className="mb-4 text-sm font-medium">结构预览</h3>
          {!content.trim() ? (
            <p className="text-sm text-slate-500">空文件</p>
          ) : parsed ? (
            <dl className="text-xs space-y-2">
              <Row k="PrivateKey" v={parsed.interface?.private_key || '—'} />
              <Row k="ListenPort" v={parsed.interface?.listen_port || '—'} />
              <Row k="Address" v={(parsed.interface?.address ?? []).join(', ') || '—'} />
              <Row k="DNS" v={(parsed.interface?.dns ?? []).join(', ') || '—'} />
              <Row k="MTU" v={parsed.interface?.mtu || '—'} />
              <Row k="Peers" v={parsed.peers?.length ?? 0} />
              {(parsed.peers ?? []).map((p, i) => (
                <li key={i} className="pl-3 border-l-2 border-slate-700 py-1">
                  <div className="font-mono text-cyan-400 break-all">{p.public_key.slice(0, 20)}…</div>
                  <div className="text-slate-500 mt-0.5">{(p.allowed_ips ?? []).join(', ')}</div>
                  {p.endpoint && <div className="text-slate-500">{p.endpoint}</div>}
                </li>
              ))}
            </dl>
          ) : parseError ? (
            <p className="text-xs text-red-400 whitespace-pre-wrap">{parseError}</p>
          ) : null}
        </Card>
      </div>

      <Modal open={creating} onClose={() => setCreating(false)} title="新建接口配置">
        {createErr && <Alert kind="error">{createErr}</Alert>}
        <Field label="接口名">
          <input
            className="w-full font-mono"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="wg0"
            autoFocus
          />
        </Field>
        <Field label="监听端口">
          <input
            className="w-full font-mono"
            value={newPort}
            onChange={(e) => setNewPort(e.target.value.replace(/\D/g, '').slice(0, 5))}
            placeholder="51820"
            inputMode="numeric"
          />
        </Field>
        <Field label="接口网段 (Address)">
          <input
            className="w-full font-mono"
            value={newAddr}
            onChange={(e) => setNewAddr(e.target.value)}
            placeholder="10.18.0.1/24"
          />
        </Field>
        <div className="mb-4 text-xs leading-5 text-slate-500">
          将立即写入 <code className="text-cyan-300">{newName.trim().replace(/\.conf$/, '')}.conf</code>
          （无需再按「保存」）：自动生成服务端私钥；NAT 转发规则的网段随「接口网段」自动计算，出口网卡默认 eth0，之后可随时修改。
        </div>
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setCreating(false)}>
            取消
          </Button>
          <Button onClick={createNow} disabled={busy}>
            {busy ? '创建中…' : '创建并保存'}
          </Button>
        </div>
      </Modal>
    </div>
  )
}

function Row({ k, v }: { k: string; v: string | number }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{k}</dt>
      <dd className="font-mono text-right truncate" title={String(v)}>
        {v}
      </dd>
    </div>
  )
}
