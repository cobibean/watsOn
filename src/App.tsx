import {
  Activity,
  AlertTriangle,
  Ban,
  CheckCircle2,
  Circle,
  Clock3,
  Code2,
  Copy,
  Database,
  ExternalLink,
  FileSearch,
  Filter,
  Folder,
  Info,
  MonitorCheck,
  RefreshCw,
  Search,
  Server,
  Settings,
  ShieldCheck,
  Square,
  Terminal,
  X,
} from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './index.css'

type ServiceCategory =
  | 'dev-server'
  | 'database'
  | 'ai-tool'
  | 'tunnel'
  | 'remote-debug'
  | 'browser-helper'
  | 'app-updater'
  | 'app-service'
  | 'system'
  | 'unknown'

type ServiceBucket = 'likely-yours' | 'normal' | 'unsure'

type Confidence = 'high' | 'medium' | 'low'

type KillVerdict = 'safe-to-stop' | 'inspect-first' | 'do-not-stop'

type KillAssessment = {
  label: string
  reason: string
  tone: 'safe' | 'caution' | 'protected'
  verdict: KillVerdict
}

type Service = {
  id: string
  pid: number
  ppid?: number
  port: number
  protocol: string
  host: string
  processName: string
  parentProcessName?: string
  command: string
  projectPath?: string
  projectName?: string
  cwd?: string
  serviceName: string
  bucket: ServiceBucket
  category: ServiceCategory
  confidence: Confidence
  confidenceReasons: string[]
  killAssessment: KillAssessment
  lsof?: {
    fd?: string
    name?: string
    node?: string
    raw?: string
    type?: string
  }
  recommendation: string
  ageSeconds?: number
  startedAt?: string
  scannerSources?: string[]
  sourceSummary?: string
  stoppable: boolean
  protectedReason?: string
}

type LsofVerdict = 'stale' | 'active' | 'good'

type DiagnosticProcess = {
  id: string
  pid: number
  ppid?: number
  processName: string
  parentProcessName?: string
  command: string
  sourceSummary: string
  recommendation: string
  reasons: string[]
  ageSeconds?: number
  startedAt?: string
  killAssessment: KillAssessment
  stoppable: boolean
  protectedReason?: string
  verdict: LsofVerdict
}

type ScanPayload = {
  diagnostics: DiagnosticProcess[]
  scannedAt: string
  platform: string
  scanner: string
  services: Service[]
  warnings: string[]
}

type ConfigPayload = {
  hasOpenRouterKey: boolean
  model: string
}

type AssistantMessage = {
  id: string
  role: 'user' | 'assistant'
  text: string
  streaming?: boolean
}

type FilterId =
  | 'all'
  | 'dev-server'
  | 'database'
  | 'ai-tool'
  | 'unsure'
  | 'long-running'
  | 'ignored'

const filters: Array<{ id: FilterId; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'dev-server', label: 'Dev servers' },
  { id: 'database', label: 'Databases' },
  { id: 'ai-tool', label: 'AI tools' },
  { id: 'unsure', label: 'Unsure' },
  { id: 'long-running', label: 'Long-running' },
  { id: 'ignored', label: 'Ignored' },
]

const emptyServices: Service[] = []
const emptyDiagnostics: DiagnosticProcess[] = []

const categoryLabels: Record<ServiceCategory, string> = {
  'dev-server': 'dev server',
  database: 'database',
  'ai-tool': 'AI tool',
  tunnel: 'tunnel',
  'remote-debug': 'remote debug',
  'browser-helper': 'browser helper',
  'app-updater': 'app updater',
  'app-service': 'app service',
  system: 'system',
  unknown: 'unknown local listener',
}

const categoryIcons: Record<ServiceCategory, typeof Server> = {
  'dev-server': Code2,
  database: Database,
  'ai-tool': MonitorCheck,
  tunnel: Activity,
  'remote-debug': Terminal,
  'browser-helper': MonitorCheck,
  'app-updater': Settings,
  'app-service': Server,
  system: Settings,
  unknown: Server,
}

function serviceKey(service: Service) {
  return `${service.protocol}:${service.port}:${service.pid}:${service.command}`
}

function formatAge(seconds?: number) {
  if (seconds === undefined || Number.isNaN(seconds)) return 'unknown'
  if (seconds < 60) return `${Math.max(1, Math.floor(seconds))}s`

  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)

  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${minutes}m`
  return `${minutes}m`
}

function formatScanTime(scannedAt?: string) {
  if (!scannedAt) return 'Not scanned yet'
  const then = new Date(scannedAt).getTime()
  const diff = Math.max(0, Date.now() - then)
  if (diff < 10_000) return 'Scanned just now'
  if (diff < 60_000) return `Scanned ${Math.round(diff / 1000)}s ago`
  return `Scanned ${Math.round(diff / 60_000)}m ago`
}

function matchesFilter(service: Service, filter: FilterId, ignored: Set<string>) {
  const ignoredService = ignored.has(serviceKey(service))

  if (filter === 'ignored') return ignoredService
  if (ignoredService) return false
  if (filter === 'all') return true
  if (filter === 'long-running') return (service.ageSeconds ?? 0) >= 3600
  if (filter === 'unsure') return service.bucket === 'unsure'
  return service.category === filter
}

function matchesSearch(service: Service, query: string) {
  if (!query.trim()) return true
  const haystack = [
    service.serviceName,
    service.processName,
    service.command,
    service.port,
    service.host,
    service.projectPath,
    service.projectName,
    service.sourceSummary,
    service.killAssessment.label,
    service.killAssessment.reason,
    service.scannerSources?.join(' '),
    service.lsof?.raw,
    service.pid,
  ]
    .join(' ')
    .toLowerCase()

  return haystack.includes(query.toLowerCase())
}

function WatsonMark() {
  return (
    <svg className="brand-mark" viewBox="0 0 40 40" aria-hidden="true">
      <path d="M20 4v32M5.5 12.5 20 4l14.5 8.5v15L20 36 5.5 27.5z" />
      <path d="m5.5 12.5 29 15M34.5 12.5l-29 15M12.5 8.5v23M27.5 8.5v23" />
    </svg>
  )
}

function SummaryItem({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Activity
  label: string
  value: number
  tone: string
}) {
  return (
    <div className="summary-item">
      <div className={`summary-icon ${tone}`}>
        <Icon size={20} strokeWidth={1.8} />
      </div>
      <div>
        <strong>{value}</strong>
        <span>{label}</span>
      </div>
    </div>
  )
}

function ConfidencePill({ value }: { value: Confidence }) {
  return <span className={`confidence confidence-${value}`}>{value}</span>
}

function KillPill({ assessment }: { assessment: KillAssessment }) {
  return (
    <span className={`kill-pill kill-${assessment.tone}`} title={assessment.reason}>
      {assessment.label}
    </span>
  )
}

function StatusDot({ service }: { service: Service }) {
  const tone =
    service.killAssessment.tone === 'safe'
      ? 'good'
      : service.killAssessment.tone === 'caution'
        ? 'warn'
        : 'quiet'

  return (
    <span className={`status-dot ${tone}`} title={service.killAssessment.reason}>
      <Circle size={10} fill="currentColor" strokeWidth={0} />
    </span>
  )
}

function LsofVerdictBadge({ diagnostic }: { diagnostic: DiagnosticProcess }) {
  const Icon =
    diagnostic.verdict === 'stale'
      ? AlertTriangle
      : diagnostic.verdict === 'good'
        ? CheckCircle2
        : Info

  return (
    <span className={`lsof-verdict ${diagnostic.verdict}`}>
      <Icon size={14} />
      {diagnostic.verdict === 'stale'
        ? 'Stuck'
        : diagnostic.verdict === 'good'
          ? 'Good'
          : 'Active'}
    </span>
  )
}

function ScanLoader() {
  return (
    <div className="scan-loader" role="status" aria-live="polite">
      <div className="scan-loader-visual" aria-hidden="true">
        <span />
        <span />
        <span />
        <span />
      </div>
      <div>
        <strong>Scanning local process evidence</strong>
        <p>Tracing listeners, lsof commands, parent processes, and kill guidance.</p>
      </div>
    </div>
  )
}

function EmptyState({
  filter,
  query,
  onRefresh,
}: {
  filter: FilterId
  query: string
  onRefresh: () => void
}) {
  return (
    <div className="empty-state">
      <ShieldCheck size={28} strokeWidth={1.6} />
      <h2>No matching services</h2>
      <p>
        {query
          ? 'Nothing matches that search.'
          : filter === 'ignored'
            ? 'Ignored services will show up here.'
            : 'The current scan did not find anything in this view.'}
      </p>
      <button className="ghost-button" type="button" onClick={onRefresh}>
        <RefreshCw size={15} />
        Refresh scan
      </button>
    </div>
  )
}

function LsofDiagnosticsPanel({
  bulkStopping,
  diagnostics,
  loading,
  onStop,
  onStopAllStuck,
  pendingPid,
}: {
  bulkStopping: boolean
  diagnostics: DiagnosticProcess[]
  loading: boolean
  onStop: (diagnostic: DiagnosticProcess) => void
  onStopAllStuck: (diagnostics: DiagnosticProcess[]) => void
  pendingPid: number | null
}) {
  const staleCount = diagnostics.filter((diagnostic) => diagnostic.verdict === 'stale').length
  const killableStuck = diagnostics.filter(
    (diagnostic) => diagnostic.verdict === 'stale' && diagnostic.stoppable,
  )

  return (
    <section className="lsof-panel" aria-label="Active lsof diagnostics">
      <div className="lsof-panel-heading">
        <div>
          <h3>
            <FileSearch size={18} />
            lsof watch
          </h3>
          <p>
            {loading
              ? 'Scanning for active lsof commands...'
              : diagnostics.length
                ? `${diagnostics.length} active lsof command${diagnostics.length === 1 ? '' : 's'} found`
                : 'No active lsof commands found'}
          </p>
        </div>
        {staleCount > 0 ? (
          <div className="lsof-heading-actions">
            <span className="lsof-alert">
              <AlertTriangle size={14} />
              {staleCount} stuck
            </span>
            <button
              className="kill-stuck-button"
              type="button"
              disabled={bulkStopping || killableStuck.length === 0}
              onClick={() => onStopAllStuck(killableStuck)}
            >
              {bulkStopping ? 'Killing...' : 'Kill all stuck'}
            </button>
          </div>
        ) : null}
      </div>

      {loading ? <ScanLoader /> : null}

      {diagnostics.length > 0 ? (
        <div className="lsof-list">
          {diagnostics.map((diagnostic) => (
            <div className="lsof-row" key={diagnostic.id}>
              <div className="lsof-main">
                <div className="lsof-row-top">
                  <LsofVerdictBadge diagnostic={diagnostic} />
                  <KillPill assessment={diagnostic.killAssessment} />
                  <span className="lsof-age">{formatAge(diagnostic.ageSeconds)}</span>
                </div>
                <strong>{diagnostic.command}</strong>
                <small>
                  PID {diagnostic.pid}
                  {diagnostic.parentProcessName
                    ? ` from ${diagnostic.parentProcessName}`
                    : diagnostic.ppid
                      ? ` from PID ${diagnostic.ppid}`
                      : ''}
                </small>
                <p>{diagnostic.sourceSummary}</p>
              </div>
              <div className="lsof-reason">
                <span>{diagnostic.reasons[0]}</span>
                <small>{diagnostic.killAssessment.reason}</small>
              </div>
              <div className="lsof-actions">
                {diagnostic.stoppable ? (
                  <button
                    className="stop-button"
                    type="button"
                    disabled={pendingPid === diagnostic.pid}
                    onClick={() => onStop(diagnostic)}
                  >
                    {pendingPid === diagnostic.pid ? 'Stopping' : 'Stop'}
                  </button>
                ) : (
                  <span className="protected-label">
                    {diagnostic.protectedReason ?? 'Protected'}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      ) : !loading ? (
        <div className="lsof-empty">
          <CheckCircle2 size={16} />
          No lsof commands are currently stuck or running.
        </div>
      ) : null}
    </section>
  )
}

function AssistantBubble({ message }: { message: AssistantMessage }) {
  if (!message.text && !message.streaming) return null

  const waiting = message.streaming && !message.text
  const className = [
    'assistant-message',
    message.role,
    message.streaming ? 'streaming' : '',
    waiting ? 'pending' : '',
  ]
    .filter(Boolean)
    .join(' ')

  return <div className={className}>{message.text || 'Consulting OpenRouter...'}</div>
}

function App() {
  const [scan, setScan] = useState<ScanPayload | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [activeFilter, setActiveFilter] = useState<FilterId>('all')
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [pendingPid, setPendingPid] = useState<number | null>(null)
  const [bulkStopping, setBulkStopping] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [showNormal, setShowNormal] = useState(false)
  const [assistantModalOpen, setAssistantModalOpen] = useState(false)
  const [assistantInput, setAssistantInput] = useState('What is this?')
  const [assistantLoading, setAssistantLoading] = useState(false)
  const [assistantMessages, setAssistantMessages] = useState<AssistantMessage[]>([])
  const [hasOpenRouterKey, setHasOpenRouterKey] = useState(false)
  const [model, setModel] = useState(() => localStorage.getItem('watson:model') ?? 'openrouter/auto')
  const [ignored, setIgnored] = useState<Set<string>>(() => {
    try {
      return new Set(JSON.parse(localStorage.getItem('watson:ignored') ?? '[]'))
    } catch {
      return new Set()
    }
  })
  const searchInputRef = useRef<HTMLInputElement>(null)
  const sidebarThreadRef = useRef<HTMLDivElement>(null)
  const modalThreadRef = useRef<HTMLDivElement>(null)

  const services = scan?.services ?? emptyServices
  const diagnostics = scan?.diagnostics ?? emptyDiagnostics
  const visibleServices = useMemo(
    () => services.filter((service) => showNormal || service.bucket !== 'normal'),
    [services, showNormal],
  )

  const filteredServices = useMemo(
    () =>
      visibleServices.filter(
        (service) =>
          matchesFilter(service, activeFilter, ignored) &&
          matchesSearch(service, query),
      ),
    [activeFilter, ignored, query, visibleServices],
  )

  const selectedService = useMemo(() => {
    return (
      filteredServices.find((service) => service.id === selectedId) ??
      filteredServices[0] ??
      visibleServices.find((service) => service.id === selectedId) ??
      null
    )
  }, [filteredServices, selectedId, visibleServices])

  const counts = useMemo(() => {
    const normalHidden = showNormal
      ? 0
      : services.filter((service) => service.bucket === 'normal').length
    const worthChecking = visibleServices.filter((service) => !ignored.has(serviceKey(service)))

    return {
      all: worthChecking.length,
      likelyYours: worthChecking.filter((service) => service.bucket === 'likely-yours').length,
      devServers: worthChecking.filter((service) => service.category === 'dev-server')
        .length,
      databases: worthChecking.filter((service) => service.category === 'database')
        .length,
      aiTools: worthChecking.filter((service) => service.category === 'ai-tool').length,
      unsure: worthChecking.filter((service) => service.bucket === 'unsure').length,
      longRunning: worthChecking.filter((service) => (service.ageSeconds ?? 0) >= 3600)
        .length,
      stoppable: worthChecking.filter((service) => service.stoppable).length,
      ignored: visibleServices.length - worthChecking.length,
      normalHidden,
      lsof: diagnostics.length,
      staleLsof: diagnostics.filter((diagnostic) => diagnostic.verdict === 'stale').length,
    }
  }, [diagnostics, ignored, services, showNormal, visibleServices])

  const refreshScan = useCallback(async () => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch('/api/scan')
      if (!response.ok) throw new Error(`Scan failed with ${response.status}`)
      const payload = (await response.json()) as ScanPayload
      setScan(payload)
      setSelectedId((current) => {
        if (current && payload.services.some((service) => service.id === current)) {
          return current
        }
        return payload.services[0]?.id ?? null
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to scan services')
    } finally {
      setLoading(false)
    }
  }, [])

  const refreshConfig = useCallback(async () => {
    try {
      const response = await fetch('/api/config')
      if (!response.ok) return
      const payload = (await response.json()) as ConfigPayload
      setHasOpenRouterKey(payload.hasOpenRouterKey)
      setModel((current) => {
        const stored = localStorage.getItem('watson:model')
        return stored ?? payload.model ?? current
      })
    } catch {
      setHasOpenRouterKey(false)
    }
  }, [])

  async function stopTarget({
    description,
    force = false,
    name,
    pid,
  }: {
    description: string
    force?: boolean
    name: string
    pid: number
  }) {
    const action = force ? 'force kill' : 'stop'
    const confirmed = window.confirm(
      `Do you want to ${action} ${name} (${description}, PID ${pid})?`,
    )
    if (!confirmed) return

    setPendingPid(pid)
    setError(null)

    try {
      const response = await fetch('/api/stop', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ force, pid }),
      })
      const payload = await response.json()
      if (!response.ok) throw new Error(payload.error ?? 'Stop request failed')
      await refreshScan()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to stop service')
    } finally {
      setPendingPid(null)
    }
  }

  async function stopService(service: Service, force = false) {
    await stopTarget({
      description: `port ${service.port}`,
      force,
      name: service.serviceName,
      pid: service.pid,
    })
  }

  async function stopDiagnostic(diagnostic: DiagnosticProcess, force = false) {
    await stopTarget({
      description: 'lsof diagnostic command',
      force,
      name: diagnostic.command || diagnostic.processName,
      pid: diagnostic.pid,
    })
  }

  async function stopStuckDiagnostics(stuckDiagnostics: DiagnosticProcess[]) {
    const targets = stuckDiagnostics.filter((diagnostic) => diagnostic.stoppable)
    if (targets.length === 0 || bulkStopping) return

    const confirmed = window.confirm(
      `Kill ${targets.length} stuck lsof command${targets.length === 1 ? '' : 's'}?`,
    )
    if (!confirmed) return

    setBulkStopping(true)
    setError(null)

    try {
      const results = await Promise.allSettled(
        targets.map(async (diagnostic) => {
          const response = await fetch('/api/stop', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ force: false, pid: diagnostic.pid }),
          })
          const payload = await response.json()
          if (!response.ok) {
            throw new Error(payload.error ?? `Unable to stop PID ${diagnostic.pid}`)
          }
          return diagnostic.pid
        }),
      )
      const failed = results.filter((result) => result.status === 'rejected')

      if (failed.length > 0) {
        setError(`Stopped ${targets.length - failed.length} stuck lsof command${targets.length - failed.length === 1 ? '' : 's'}; ${failed.length} failed.`)
      }

      await refreshScan()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to kill stuck lsof commands')
    } finally {
      setBulkStopping(false)
    }
  }

  function toggleIgnored(service: Service) {
    const key = serviceKey(service)
    setIgnored((current) => {
      const next = new Set(current)
      if (next.has(key)) {
        next.delete(key)
      } else {
        next.add(key)
      }
      localStorage.setItem('watson:ignored', JSON.stringify([...next]))
      return next
    })
  }

  async function copyValue(value: string, key: string) {
    await navigator.clipboard.writeText(value)
    setCopiedKey(key)
    window.setTimeout(() => setCopiedKey(null), 1200)
  }

  async function askAssistant(
    question = assistantInput,
    service = selectedService,
    options: { openModal?: boolean } = {},
  ) {
    if (options.openModal && service) setAssistantModalOpen(true)
    if (!service || !question.trim() || assistantLoading) return

    const userMessage: AssistantMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      text: question.trim(),
    }
    const assistantMessageId = `assistant-${Date.now()}`
    const streamingMessage: AssistantMessage = {
      id: assistantMessageId,
      role: 'assistant',
      text: '',
      streaming: true,
    }
    setSelectedId(service.id)
    setAssistantMessages((current) =>
      [...current, userMessage, streamingMessage].slice(-10),
    )
    setAssistantInput('')
    setAssistantLoading(true)

    try {
      const response = await fetch('/api/ask/stream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, question: question.trim(), service }),
      })

      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        throw new Error(payload?.error ?? 'OpenRouter request failed')
      }

      if (!response.body) throw new Error('OpenRouter returned no stream.')

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let streamedText = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        streamedText += decoder.decode(value, { stream: true })
        setAssistantMessages((current) =>
          current.map((message) =>
            message.id === assistantMessageId
              ? { ...message, text: streamedText, streaming: true }
              : message,
          ),
        )
      }

      if (!streamedText.trim()) {
        streamedText = 'OpenRouter returned no user-facing answer. Try asking again.'
      }

      setAssistantMessages((current) =>
        current.map((message) =>
          message.id === assistantMessageId
            ? { ...message, text: streamedText, streaming: false }
            : message,
        ),
      )
    } catch (err) {
      const text =
        err instanceof Error
          ? err.message
          : 'Unable to ask OpenRouter. Check OPENROUTER_API_KEY and try again.'
      setAssistantMessages((current) =>
        current.map((message) =>
          message.id === assistantMessageId
            ? { ...message, text, streaming: false }
            : message,
        ),
      )
    } finally {
      setAssistantLoading(false)
    }
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refreshScan()
      void refreshConfig()
    }, 0)

    return () => {
      window.clearTimeout(timer)
    }
  }, [refreshConfig, refreshScan])

  useEffect(() => {
    for (const thread of [sidebarThreadRef.current, modalThreadRef.current]) {
      if (thread) thread.scrollTop = thread.scrollHeight
    }
  }, [assistantMessages, assistantModalOpen])

  useEffect(() => {
    if (!assistantModalOpen) return

    const previousOverflow = document.body.style.overflow
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setAssistantModalOpen(false)
    }

    document.body.style.overflow = 'hidden'
    window.addEventListener('keydown', handleKeyDown)

    return () => {
      document.body.style.overflow = previousOverflow
      window.removeEventListener('keydown', handleKeyDown)
    }
  }, [assistantModalOpen])

  return (
    <main className="app-shell">
      <header className="topbar">
        <div className="brand">
          <WatsonMark />
          <div>
            <h1>watsOn</h1>
            <p>Local services, clearly accounted for.</p>
          </div>
        </div>

        <div className="topbar-actions">
          <button
            className="refresh-button"
            type="button"
            onClick={refreshScan}
            disabled={loading}
          >
            <RefreshCw size={17} className={loading ? 'spin' : ''} />
            Refresh
          </button>
          <span className="scan-time">
            {formatScanTime(scan?.scannedAt)}
            <span className="live-dot" />
          </span>
          <button
            className="icon-button"
            type="button"
            aria-expanded={settingsOpen}
            aria-label="Settings"
            onClick={() => setSettingsOpen((open) => !open)}
          >
            <Settings size={18} />
          </button>
          {settingsOpen ? (
            <div className="settings-popover">
              <div>
                <strong>View options</strong>
                <p>Normal system/app plumbing stays protected.</p>
              </div>
              <div className={`settings-status ${hasOpenRouterKey ? 'connected' : ''}`}>
                <span>{hasOpenRouterKey ? 'OpenRouter connected' : 'OpenRouter not configured'}</span>
                <small>{hasOpenRouterKey ? model : 'Set OPENROUTER_API_KEY in .env.local'}</small>
              </div>
              <label className="toggle-row">
                <input
                  type="checkbox"
                  checked={showNormal}
                  onChange={(event) => setShowNormal(event.target.checked)}
                />
                <span>Show normal services</span>
              </label>
              <label className="settings-field">
                <span>OpenRouter model</span>
                <input
                  value={model}
                  onChange={(event) => {
                    setModel(event.target.value)
                    localStorage.setItem('watson:model', event.target.value)
                  }}
                  placeholder="openrouter/auto"
                />
              </label>
              <button
                className="settings-action"
                type="button"
                onClick={() => {
                  localStorage.removeItem('watson:ignored')
                  setIgnored(new Set())
                }}
              >
                Reset ignored
              </button>
            </div>
          ) : null}
        </div>
      </header>

      <section className="workspace">
        <aside className="summary-rail" aria-label="Service summary">
          <div className="section-label">Summary</div>
          <SummaryItem icon={Activity} label="Worth checking" value={counts.all} tone="teal" />
          <SummaryItem
            icon={FileSearch}
            label="Active lsof"
            value={counts.lsof}
            tone={counts.staleLsof > 0 ? 'danger' : 'violet'}
          />
          <SummaryItem
            icon={Code2}
            label="Likely yours"
            value={counts.likelyYours}
            tone="amber"
          />
          <SummaryItem
            icon={Clock3}
            label="Unsure"
            value={counts.unsure}
            tone="violet"
          />
          <SummaryItem icon={ShieldCheck} label="Hidden normal" value={counts.normalHidden} tone="green" />

          <div className="filter-block">
            <div className="section-label">Filters</div>
            {filters.map((filter) => {
              const count =
                filter.id === 'all'
                  ? counts.all
                  : filter.id === 'dev-server'
                    ? counts.devServers
                    : filter.id === 'database'
                      ? counts.databases
                      : filter.id === 'ai-tool'
                        ? counts.aiTools
                        : filter.id === 'unsure'
                          ? counts.unsure
                          : filter.id === 'long-running'
                            ? counts.longRunning
                            : counts.ignored

              return (
                <button
                  key={filter.id}
                  className={`filter-button ${activeFilter === filter.id ? 'active' : ''}`}
                  type="button"
                  onClick={() => setActiveFilter(filter.id)}
                >
                  <span>{filter.label}</span>
                  <span>{count}</span>
                </button>
              )
            })}
          </div>

          <div className="privacy-note">
            <ShieldCheck size={16} />
            <p>Normal system and app plumbing is hidden from this list by default.</p>
          </div>
        </aside>

        <section className="service-panel" aria-label="Running services">
          <div className="panel-heading">
            <div>
              <h2>Worth checking</h2>
              <p>
                {loading
                  ? 'Scanning local listeners...'
                  : `${filteredServices.length} of ${visibleServices.length} local listeners`}
              </p>
            </div>

            <div className="search-row">
              <label className="search-box">
                <Search size={17} />
                <input
                  ref={searchInputRef}
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  placeholder="Search by name, port, process..."
                />
              </label>
              <button
                className="icon-button"
                type="button"
                aria-label="Focus search"
                onClick={() => {
                  searchInputRef.current?.focus()
                  searchInputRef.current?.select()
                }}
              >
                <Filter size={17} />
              </button>
            </div>
          </div>

          {error ? (
            <div className="error-banner" role="alert">
              <X size={16} />
              {error}
            </div>
          ) : null}

          <LsofDiagnosticsPanel
            bulkStopping={bulkStopping}
            diagnostics={diagnostics}
            loading={loading}
            pendingPid={pendingPid}
            onStop={(diagnostic) => {
              void stopDiagnostic(diagnostic)
            }}
            onStopAllStuck={(stuckDiagnostics) => {
              void stopStuckDiagnostics(stuckDiagnostics)
            }}
          />

          {scan?.warnings.length ? (
            <div className="warning-strip">
              {scan.warnings.map((warning) => (
                <span key={warning}>{warning}</span>
              ))}
            </div>
          ) : null}

          <div className="service-table">
            <div className="service-head">
              <span>Status</span>
              <span>Service</span>
              <span>Port</span>
              <span>Process / PID</span>
              <span>Command / Project</span>
              <span>Age</span>
              <span>Kill read</span>
              <span>Action</span>
            </div>

            {filteredServices.length === 0 ? (
              <EmptyState filter={activeFilter} query={query} onRefresh={refreshScan} />
            ) : (
              filteredServices.map((service) => {
                const Icon = categoryIcons[service.category]
                const selected = selectedService?.id === service.id
                const ignoredService = ignored.has(serviceKey(service))

                return (
                  <div
                    key={service.id}
                    className={`service-row ${selected ? 'selected' : ''}`}
                    role="row"
                    aria-selected={selected}
                    tabIndex={0}
                    onClick={() => setSelectedId(service.id)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault()
                        setSelectedId(service.id)
                      }
                    }}
                  >
                    <span className="cell status-cell">
                      <StatusDot service={service} />
                    </span>
                    <span className="cell service-cell">
                      <Icon size={17} />
                      <span>
                        <strong>{service.serviceName}</strong>
                        <small>{categoryLabels[service.category]}</small>
                      </span>
                    </span>
                    <span className="cell mono-cell">
                      <strong>{service.port}</strong>
                      <small>{service.protocol}</small>
                    </span>
                    <span className="cell">
                      <strong>{service.processName}</strong>
                      <small>PID {service.pid}</small>
                    </span>
                    <span className="cell command-cell">
                      <strong>{service.command || service.processName}</strong>
                      <small>{service.projectPath ?? service.cwd ?? '(no project)'}</small>
                    </span>
                    <span className="cell age-cell">{formatAge(service.ageSeconds)}</span>
                    <span className="cell">
                      <KillPill assessment={service.killAssessment} />
                      <small className="reason-text">{service.killAssessment.reason}</small>
                    </span>
                    <span className="cell action-cell">
                      <button
                        className="ask-row-button"
                        type="button"
                        disabled={assistantLoading}
                        onClick={(event) => {
                          event.stopPropagation()
                          void askAssistant('What is this?', service, { openModal: true })
                        }}
                      >
                        What is this?
                      </button>
                      {service.stoppable && !ignoredService ? (
                        <button
                          className="stop-button"
                          type="button"
                          disabled={pendingPid === service.pid}
                          onClick={(event) => {
                            event.stopPropagation()
                            void stopService(service)
                          }}
                        >
                          {pendingPid === service.pid ? 'Stopping' : 'Stop'}
                        </button>
                      ) : (
                        <span className="protected-label">
                          {ignoredService ? 'Ignored' : service.killAssessment.label}
                        </span>
                      )}
                    </span>
                  </div>
                )
              })
            )}
          </div>

          <footer className="table-footer">
            <span>
              Platform: <strong>{scan?.platform ?? 'unknown'}</strong>
            </span>
            <span>
              Hidden normal: <strong>{counts.normalHidden}</strong>
            </span>
            <span>
              Scanner: <strong>{scan?.scanner ?? 'waiting'}</strong>
            </span>
          </footer>
        </section>

        <aside className="inspector" aria-label="Selected service details">
          {selectedService ? (
            <>
              <div className="inspector-title">
                <div>
                  <StatusDot service={selectedService} />
                  <h2>{selectedService.serviceName}</h2>
                </div>
                <button
                  className="icon-button"
                  type="button"
                  aria-label="Clear selection"
                  onClick={() => setSelectedId(null)}
                >
                  <X size={17} />
                </button>
              </div>

              <div className="tag-row">
                <KillPill assessment={selectedService.killAssessment} />
                <ConfidencePill value={selectedService.confidence} />
                {(selectedService.ageSeconds ?? 0) >= 3600 ? (
                  <span className="tag warn">Long-running</span>
                ) : null}
                <span className="tag">{categoryLabels[selectedService.category]}</span>
                <span className="tag">{selectedService.bucket.replace('-', ' ')}</span>
              </div>

              <dl className="detail-list">
                <div>
                  <dt>Port</dt>
                  <dd>
                    {selectedService.port} / {selectedService.protocol}
                  </dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd className="listening">Listening</dd>
                </div>
                <div>
                  <dt>Process</dt>
                  <dd>
                    {selectedService.processName} (PID {selectedService.pid})
                  </dd>
                </div>
                <div>
                  <dt>Age</dt>
                  <dd>{formatAge(selectedService.ageSeconds)}</dd>
                </div>
                <div>
                  <dt>Source</dt>
                  <dd>{selectedService.sourceSummary ?? 'unknown'}</dd>
                </div>
                <div>
                  <dt>Scanner</dt>
                  <dd>{selectedService.scannerSources?.join(' + ') ?? scan?.scanner ?? 'unknown'}</dd>
                </div>
                <div>
                  <dt>Parent</dt>
                  <dd>
                    {selectedService.parentProcessName
                      ? `${selectedService.parentProcessName} (${selectedService.ppid})`
                      : selectedService.ppid
                        ? `PID ${selectedService.ppid}`
                        : 'unknown'}
                  </dd>
                </div>
                <div className="detail-wide">
                  <dt>Why shown</dt>
                  <dd>{selectedService.confidenceReasons[0]}</dd>
                </div>
                <div className="detail-wide">
                  <dt>Kill read</dt>
                  <dd>{selectedService.killAssessment.reason}</dd>
                </div>
                {selectedService.lsof?.raw ? (
                  <div className="detail-wide">
                    <dt>lsof evidence</dt>
                    <dd className="lsof-raw">{selectedService.lsof.raw}</dd>
                  </div>
                ) : null}
              </dl>

              <div className={`recommendation-note ${selectedService.killAssessment.tone}`}>
                {selectedService.recommendation}
              </div>

              <section className="assistant-card" aria-label="Service assistant">
                <div className="assistant-header">
                  <div>
                    <strong>Ask watsOn</strong>
                    <span>{hasOpenRouterKey ? 'OpenRouter connected' : 'OpenRouter key needed'}</span>
                  </div>
                  <button
                    className="mini-button"
                    type="button"
                    disabled={assistantLoading}
                    onClick={() =>
                      void askAssistant('What is this?', selectedService, { openModal: true })
                    }
                  >
                    {assistantLoading ? 'Asking...' : 'What is this?'}
                  </button>
                </div>
                {!hasOpenRouterKey ? (
                  <div className="assistant-config-note">
                    Set <code>OPENROUTER_API_KEY</code> in <code>.env.local</code> and restart
                    watsOn to enable model-backed answers.
                  </div>
                ) : null}
                <div className="assistant-thread" ref={sidebarThreadRef} aria-live="polite">
                  {assistantMessages.length === 0 ? (
                    <p>
                      Ask about the selected process. The server sends the selected row evidence
                      plus the system prompt to OpenRouter.
                    </p>
                  ) : (
                    assistantMessages.map((message) => (
                      <AssistantBubble key={message.id} message={message} />
                    ))
                  )}
                </div>
                <form
                  className="assistant-form"
                  onSubmit={(event) => {
                    event.preventDefault()
                    void askAssistant(assistantInput, selectedService, { openModal: true })
                  }}
                >
                  <input
                    value={assistantInput}
                    onChange={(event) => setAssistantInput(event.target.value)}
                    placeholder="Ask what it is, why it appears, or whether to stop it"
                  />
                  <button type="submit" disabled={!assistantInput.trim()}>
                    {assistantLoading ? '...' : 'Ask'}
                  </button>
                </form>
              </section>

              <div className="copy-group">
                <DetailCopy
                  label="Command"
                  value={selectedService.command || selectedService.processName}
                  copied={copiedKey === 'command'}
                  onCopy={() =>
                    copyValue(selectedService.command || selectedService.processName, 'command')
                  }
                />
                <DetailCopy
                  label="Host"
                  value={`${selectedService.host}:${selectedService.port}`}
                  copied={copiedKey === 'host'}
                  onCopy={() =>
                    copyValue(`${selectedService.host}:${selectedService.port}`, 'host')
                  }
                />
                <DetailCopy
                  label="Project"
                  value={selectedService.projectPath ?? selectedService.cwd ?? 'unknown'}
                  copied={copiedKey === 'project'}
                  onCopy={() =>
                    copyValue(selectedService.projectPath ?? selectedService.cwd ?? '', 'project')
                  }
                />
                <DetailCopy
                  label="Source"
                  value={selectedService.sourceSummary ?? 'unknown'}
                  copied={copiedKey === 'source'}
                  onCopy={() => copyValue(selectedService.sourceSummary ?? '', 'source')}
                />
              </div>

              <div className="action-stack">
                <button
                  className="action-card"
                  type="button"
                  disabled={!selectedService.stoppable || pendingPid === selectedService.pid}
                  onClick={() => void stopService(selectedService)}
                >
                  <span className="action-icon teal">
                    <Square size={15} />
                  </span>
                  <span>
                    <strong>Stop process</strong>
                    <small>
                      {selectedService.protectedReason ?? selectedService.killAssessment.reason}
                    </small>
                  </span>
                  <ExternalLink size={15} />
                </button>
                <button
                  className="action-card"
                  type="button"
                  disabled={!selectedService.stoppable || pendingPid === selectedService.pid}
                  onClick={() => void stopService(selectedService, true)}
                >
                  <span className="action-icon quiet">
                    <Terminal size={15} />
                  </span>
                  <span>
                    <strong>Kill process</strong>
                    <small>
                      {selectedService.killAssessment.verdict === 'safe-to-stop'
                        ? 'Force kill only if stop does not work'
                        : 'Use only after confirming the owner'}
                    </small>
                  </span>
                  <ExternalLink size={15} />
                </button>
              </div>

              {(selectedService.ageSeconds ?? 0) >= 7200 ? (
                <div className="long-note">
                  This has been listening for over two hours. Check whether it is still needed.
                </div>
              ) : null}

              <button
                className="ignore-button"
                type="button"
                onClick={() => toggleIgnored(selectedService)}
              >
                <Ban size={15} />
                {ignored.has(serviceKey(selectedService))
                  ? 'Remove from ignore list'
                  : 'Add to ignore list'}
              </button>
            </>
          ) : (
            <div className="empty-inspector">
              <Folder size={24} />
              <p>Select a service to inspect its command, owner process, and stop options.</p>
            </div>
          )}
        </aside>
      </section>

      {assistantModalOpen && selectedService ? (
        <div
          className="assistant-modal-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setAssistantModalOpen(false)
          }}
        >
          <section
            className="assistant-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="assistant-modal-title"
          >
            <header className="assistant-modal-header">
              <div className="assistant-modal-title">
                <StatusDot service={selectedService} />
                <div>
                  <span>Ask watsOn</span>
                  <h2 id="assistant-modal-title">{selectedService.serviceName}</h2>
                  <p>
                    {selectedService.processName} (PID {selectedService.pid}) on port{' '}
                    {selectedService.port}
                  </p>
                </div>
              </div>
              <button
                className="icon-button"
                type="button"
                aria-label="Close assistant"
                onClick={() => setAssistantModalOpen(false)}
              >
                <X size={17} />
              </button>
            </header>

            <div className="assistant-modal-meta">
              <KillPill assessment={selectedService.killAssessment} />
              <ConfidencePill value={selectedService.confidence} />
              <span className="tag">{categoryLabels[selectedService.category]}</span>
              <span className="tag">{selectedService.bucket.replace('-', ' ')}</span>
              <span className={`assistant-connection ${hasOpenRouterKey ? 'connected' : ''}`}>
                {hasOpenRouterKey ? 'OpenRouter connected' : 'OpenRouter key needed'}
              </span>
            </div>

            {!hasOpenRouterKey ? (
              <div className="assistant-config-note">
                Set <code>OPENROUTER_API_KEY</code> in <code>.env.local</code> and restart watsOn
                to enable model-backed answers.
              </div>
            ) : null}

            <div className="assistant-evidence-grid">
              <div>
                <span>Kill read</span>
                <p>{selectedService.killAssessment.reason}</p>
              </div>
              <div>
                <span>Source</span>
                <p>{selectedService.sourceSummary ?? 'unknown'}</p>
              </div>
              <div>
                <span>Why shown</span>
                <p>{selectedService.confidenceReasons[0]}</p>
              </div>
              <div>
                <span>Recommendation</span>
                <p>{selectedService.recommendation}</p>
              </div>
              <div className="assistant-evidence-wide">
                <span>Command</span>
                <code>{selectedService.command || selectedService.processName}</code>
              </div>
            </div>

            <div className="assistant-thread modal-thread" ref={modalThreadRef} aria-live="polite">
              {assistantMessages.length === 0 ? (
                <p>
                  Ask about this listener. watsOn sends the selected row evidence and system prompt
                  to OpenRouter.
                </p>
              ) : (
                assistantMessages.map((message) => (
                  <AssistantBubble key={message.id} message={message} />
                ))
              )}
            </div>

            <form
              className="assistant-form modal-form"
              onSubmit={(event) => {
                event.preventDefault()
                void askAssistant()
              }}
            >
              <input
                value={assistantInput}
                onChange={(event) => setAssistantInput(event.target.value)}
                placeholder="Ask what it is, why it appears, or whether to stop it"
              />
              <button type="submit" disabled={!assistantInput.trim() || assistantLoading}>
                {assistantLoading ? '...' : 'Ask'}
              </button>
            </form>
          </section>
        </div>
      ) : null}
    </main>
  )
}

function DetailCopy({
  copied,
  label,
  onCopy,
  value,
}: {
  copied: boolean
  label: string
  onCopy: () => void
  value: string
}) {
  return (
    <div className="copy-field">
      <span>{label}</span>
      <button type="button" onClick={onCopy} disabled={!value || value === 'unknown'}>
        <code>{value || 'unknown'}</code>
        <Copy size={14} />
      </button>
      {copied ? <small>Copied</small> : null}
    </div>
  )
}

export default App
