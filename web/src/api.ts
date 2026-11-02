// Thin fetch wrapper handling JSON, CSRF header and auth errors.

let csrf = ''

export function setCsrf(token: string) {
  csrf = token
}

export interface ApiErrorData {
  error?: string
  parse_error?: string
  [key: string]: unknown
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

export class ApiError extends Error {
  status: number
  data: ApiErrorData | null
  constructor(status: number, message: string, data?: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.data = isRecord(data) ? data : null
  }
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : '请求失败'
}

export function errorData(error: unknown): ApiErrorData | null {
  return error instanceof ApiError ? error.data : null
}

async function throwResponseError(res: Response, url: string): Promise<never> {
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    /* empty or non-JSON error body */
  }
  if (
    res.status === 401 &&
    !url.startsWith('/api/me') &&
    !url.startsWith('/api/auth') &&
    !url.startsWith('/api/setup')
  ) {
    setCsrf('')
    window.location.reload()
  }
  const payload = isRecord(data) ? data : null
  const msg =
    (typeof payload?.error === 'string' && payload.error) ||
    (typeof payload?.parse_error === 'string' && payload.parse_error) ||
    res.statusText ||
    `请求失败（HTTP ${res.status}）`
  throw new ApiError(res.status, msg, data)
}

async function request<T = unknown>(method: string, url: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf
  const res = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) {
    return throwResponseError(res, url)
  }
  let data: unknown = null
  try {
    data = await res.json()
  } catch {
    /* empty body */
  }
  return data as T
}

export const api = {
  get: <T = unknown>(url: string) => request<T>('GET', url),
  post: <T = unknown>(url: string, body?: unknown) => request<T>('POST', url, body),
  put: <T = unknown>(url: string, body?: unknown) => request<T>('PUT', url, body),
  del: <T = unknown>(url: string) => request<T>('DELETE', url),
  getBlob: async (url: string) => {
    const res = await fetch(url, { credentials: 'same-origin' })
    if (!res.ok) return throwResponseError(res, url)
    return res.blob()
  },
}

// --- shared types ------------------------------------------------------------

export interface PeerStatus {
  public_key: string
  preshared_key_set: boolean
  endpoint: string
  allowed_ips: string[]
  latest_handshake: string
  latest_handshake_ago_seconds: number
  rx_bytes: number
  tx_bytes: number
  keepalive_seconds: number
}

export interface InterfaceStatus {
  name: string
  public_key: string
  listen_port: number
  fwmark: number
  peers: PeerStatus[]
}

export interface VaultEntry {
  id: string
  name: string
  iface?: string
  public_key: string
  has_private_key: boolean
  has_preshared_key: boolean
  loaded: boolean
  pending_apply: boolean
  runtime_loaded?: boolean
  needs_apply: boolean
  runtime_error?: string
  config_error?: string
  address: string[]
  dns: string[]
  server_endpoint: string
  server_pub_key: string
  allowed_ips: string[]
  keepalive: number
  notes: string
  created_at: string
  updated_at: string
}

// --- formatting helpers ---------------------------------------------------------

export function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function fmtAgo(seconds: number): string {
  if (!seconds || seconds < 0) return '从未'
  if (seconds < 60) return `${seconds} 秒前`
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

export function shortKey(k: string): string {
  return k.length > 16 ? k.slice(0, 8) + '…' + k.slice(-6) : k
}
