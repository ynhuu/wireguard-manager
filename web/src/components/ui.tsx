import { useEffect, useRef, useState, type ReactNode } from 'react'

const toastNodes = new Set<HTMLElement>()
const toastEvents = new EventTarget()

function notifyToastLayout() {
  toastEvents.dispatchEvent(new Event('change'))
}

// 按 DOM 先后顺序堆叠，避免隐藏后重现的 Toast 排到末尾
function sortedToastNodes() {
  return [...toastNodes].sort((a, b) =>
    a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1,
  )
}

window.addEventListener('resize', notifyToastLayout)

export function PageTitle({ title, desc, right }: { title: string; desc?: string; right?: ReactNode }) {
  return (
    <div className="mb-8 flex flex-col gap-5 border-b border-slate-800 pb-6 xl:flex-row xl:items-end xl:justify-between">
      <div className="page-title-copy xl:flex-1">
        <div className="eyebrow mb-3">WireGuard / 控制中心</div>
        <h1 className="display-title text-slate-100">{title}</h1>
        {desc && <p className="mt-2 max-w-2xl text-sm text-slate-500">{desc}</p>}
      </div>
      {right && <div className="page-title-actions w-full min-w-0 flex flex-wrap items-center gap-2 xl:ml-auto xl:w-auto xl:justify-end xl:shrink-0">{right}</div>}
    </div>
  )
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`surface-card rounded-2xl ${className}`}>{children}</div>
}

export function Button({
  children,
  onClick,
  variant = 'primary',
  type = 'button',
  disabled,
  className = '',
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'primary' | 'ghost' | 'danger'
  type?: 'button' | 'submit'
  disabled?: boolean
  className?: string
}) {
  const styles = {
    primary: 'bg-cyan-600 hover:bg-cyan-500 text-white border-transparent shadow-sm',
    ghost: 'bg-transparent hover:bg-slate-800 text-slate-300 border-slate-700',
    danger: 'bg-transparent hover:bg-red-950 text-red-400 border-red-900',
  }[variant]
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-xl border px-4 py-2.5 text-sm font-medium transition-all hover:-translate-y-px disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}
    >
      {children}
    </button>
  )
}

export function Alert({ kind, children }: { kind: 'error' | 'info'; children: ReactNode }) {
  const styles = {
    error: 'border-red-900 bg-red-950/50 text-red-300',
    info: 'border-slate-700 bg-slate-800/60 text-slate-300',
  }[kind]
  return <div className={`mb-4 flex items-start gap-3 rounded-xl border px-4 py-3 text-sm ${styles}`}>{children}</div>
}

export function Toast({ kind, children }: { kind: 'error' | 'ok'; children: ReactNode }) {
  const [visible, setVisible] = useState(true)
  const [top, setTop] = useState(16)
  const nodeRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    setVisible(true)
    if (kind === 'error') {
      // 内容变化可能改变高度，通知其余 Toast 重新计算堆叠位置
      requestAnimationFrame(notifyToastLayout)
      return
    }
    const timer = window.setTimeout(() => setVisible(false), 4200)
    return () => window.clearTimeout(timer)
  }, [children, kind])

  useEffect(() => {
    const node = nodeRef.current
    if (!node) return
    const reposition = () => {
      let nextTop = 16
      for (const previous of sortedToastNodes()) {
        if (previous === node) break
        nextTop += previous.getBoundingClientRect().height + 8
      }
      setTop(nextTop)
    }
    toastNodes.add(node)
    toastEvents.addEventListener('change', reposition)
    requestAnimationFrame(() => {
      reposition()
      notifyToastLayout()
    })
    return () => {
      toastNodes.delete(node)
      toastEvents.removeEventListener('change', reposition)
      notifyToastLayout()
    }
  }, [visible])

  if (!visible) return null
  const styles = {
    error: 'toast-error',
    ok: 'toast-ok',
  }[kind]
  return (
    <div
      ref={nodeRef}
      role={kind === 'error' ? 'alert' : 'status'}
      aria-live={kind === 'error' ? 'assertive' : 'polite'}
      aria-atomic="true"
      style={{ top: `calc(${top}px + env(safe-area-inset-top, 0px))` }}
      className={`toast-surface fixed right-4 z-60 flex max-w-[min(420px,calc(100vw-32px))] items-start gap-3 rounded-xl border px-4 py-3 text-sm shadow-2xl backdrop-blur-md ${styles}`}
    >
      <span className="h-2 w-2 shrink-0 self-center rounded-full bg-current" />
      <span className="flex-1 leading-5">{children}</span>
    </div>
  )
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="mb-5 block">
      <span className="mb-2 block text-[11px] font-semibold uppercase tracking-[.12em] text-slate-500">{label}</span>
      {children}
    </label>
  )
}

export function Modal({ open, onClose, title, children, wide, dismissible = true }: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  wide?: boolean
  dismissible?: boolean
}) {
  useEffect(() => {
    if (!open || !dismissible) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, dismissible, onClose])

  if (!open) return null
  return (
    <div className="safe-overlay fixed inset-0 z-50 overflow-y-auto no-scrollbar">
      <div className="fixed inset-0 bg-black/55 backdrop-blur-sm" onClick={dismissible ? onClose : undefined} />
      <div className="relative flex min-h-full items-center justify-center">
        <div className={`w-full rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl ${wide ? 'max-w-2xl' : 'max-w-md'}`}>
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
            <h2 className="font-semibold text-slate-100">{title}</h2>
            {dismissible && <button onClick={onClose} className="rounded-lg px-2 py-1 text-lg text-slate-500 transition-colors hover:bg-slate-800 hover:text-slate-200" aria-label="关闭">×</button>}
          </div>
          <div className="p-5">{children}</div>
        </div>
      </div>
    </div>
  )
}

export function Badge({ online }: { online: boolean }) {
  return online ? (
    <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
      <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />在线
    </span>
  ) : (
    <span className="inline-flex items-center gap-1.5 text-xs text-slate-500">
      <span className="h-1.5 w-1.5 rounded-full bg-slate-600" />离线
    </span>
  )
}
