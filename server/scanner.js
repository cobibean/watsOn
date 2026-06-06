import { execFile } from 'node:child_process'
import { homedir } from 'node:os'
import { basename } from 'node:path'

const COMMAND_TIMEOUT = 2600
const LSOF_EVIDENCE_TIMEOUT = 1800
const MAX_BUFFER = 1024 * 1024 * 8
const STALE_LSOF_SECONDS = 20

const systemProcessNames = new Set([
  'ControlCenter',
  'WindowServer',
  'apsd',
  'io.tailscale.ipn.macsys.network-extension',
  'locationd',
  'launchd',
  'mDNSResponder',
  'rapportd',
  'syspolicyd',
  'systemd',
  'symptomsd',
  'trustd',
  'tailscaled',
])

const normalAppPatterns = [
  /Microsoft AutoUpdate/i,
  /GoogleUpdater|GoogleSoftwareUpdate|ksadmin|ksfetch/i,
  /com\.apple\./i,
  /\/Applications\/[^/]+\.app\/Contents\/.*Helper/i,
  /\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i,
  /\/Users\/[^/]+\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i,
  /\/System\//i,
  /\/usr\/libexec\//i,
  /\/Library\/Apple\//i,
]

const browserPatterns = [
  /Chrome Helper|Google Chrome/i,
  /Safari/i,
  /firefox/i,
  /Microsoft Edge/i,
  /Arc Helper|Arc\.app/i,
]

const devRules = [
  { name: 'Vite', category: 'dev-server', test: /(^|\s)(vite|vite-node)(\s|$)/i },
  { name: 'Next.js', category: 'dev-server', test: /next(\s+dev| dev|\s)/i },
  { name: 'Astro', category: 'dev-server', test: /astro\s+dev/i },
  { name: 'Nuxt', category: 'dev-server', test: /nuxt\s+(dev|preview)/i },
  { name: 'Remix', category: 'dev-server', test: /remix\s+dev/i },
  { name: 'SvelteKit', category: 'dev-server', test: /svelte-kit|vite.*svelte/i },
  { name: 'Storybook', category: 'dev-server', test: /storybook|start-storybook/i },
  { name: 'Prisma Studio', category: 'dev-server', test: /prisma\s+studio/i },
  { name: 'Webpack', category: 'dev-server', test: /webpack-dev-server|webpack serve/i },
  { name: 'Python HTTP Server', category: 'dev-server', test: /python.*http\.server/i },
  { name: 'Django', category: 'dev-server', test: /manage\.py\s+runserver/i },
  { name: 'Flask', category: 'dev-server', test: /flask\s+run/i },
  { name: 'Uvicorn', category: 'dev-server', test: /uvicorn/i },
  { name: 'Rails', category: 'dev-server', test: /(rails|bin\/rails)\s+s|puma/i },
  { name: 'Spring Boot', category: 'dev-server', test: /spring-boot|org\.springframework/i },
  { name: 'Bun', category: 'dev-server', test: /\bbun\b.*(dev|serve|run)/i },
  { name: 'Deno', category: 'dev-server', test: /\bdeno\b.*(task|run|serve)/i },
  { name: 'PostgreSQL', category: 'database', test: /postgres|postmaster/i },
  { name: 'Redis', category: 'database', test: /redis-server/i },
  { name: 'MySQL', category: 'database', test: /mysqld/i },
  { name: 'MongoDB', category: 'database', test: /mongod/i },
  { name: 'Elasticsearch', category: 'database', test: /elasticsearch/i },
  { name: 'Ollama', category: 'ai-tool', test: /ollama/i },
  { name: 'LocalAI', category: 'ai-tool', test: /localai/i },
  { name: 'LM Studio', category: 'ai-tool', test: /lm studio|lmstudio/i },
  { name: 'ngrok', category: 'tunnel', test: /ngrok/i },
  { name: 'Cloudflare Tunnel', category: 'tunnel', test: /cloudflared/i },
  { name: 'Browser automation', category: 'remote-debug', test: /remote-debugging-port|playwright|puppeteer|cypress/i },
]

const knownPorts = new Map([
  [3000, ['Next.js / Node', 'dev-server']],
  [3001, ['Node dev server', 'dev-server']],
  [4200, ['Angular', 'dev-server']],
  [4321, ['Astro', 'dev-server']],
  [5000, ['Local web server', 'dev-server']],
  [5173, ['Vite', 'dev-server']],
  [5174, ['Vite', 'dev-server']],
  [5555, ['Prisma Studio', 'dev-server']],
  [6006, ['Storybook', 'dev-server']],
  [7000, ['Local web server', 'dev-server']],
  [8000, ['Local web server', 'dev-server']],
  [8080, ['Local web server', 'dev-server']],
  [9222, ['Chrome DevTools', 'remote-debug']],
  [1025, ['MailHog / Mailpit', 'dev-server']],
  [4040, ['ngrok inspector', 'tunnel']],
  [4369, ['EPMD', 'database']],
  [5432, ['PostgreSQL', 'database']],
  [6379, ['Redis', 'database']],
  [27017, ['MongoDB', 'database']],
  [3306, ['MySQL', 'database']],
  [9200, ['Elasticsearch', 'database']],
  [11434, ['Ollama', 'ai-tool']],
])

export async function scanServices({ appPorts = [] } = {}) {
  const warnings = []
  const startedAt = new Date()
  const listeners = await scanListeners(warnings)
  const lsofEvidence = await scanLsofEvidence(warnings)
  const appPortSet = new Set(appPorts.map(Number))
  const uniqueListeners = dedupeListeners(
    listeners.filter((listener) => !appPortSet.has(listener.port)),
  )
  const lsofEvidenceMap = new Map(
    lsofEvidence.map((entry) => [listenerEvidenceKey(entry.pid, entry.port), entry]),
  )
  const processMap = await getProcessDetails(uniqueListeners.map((listener) => listener.pid))
  const parentMap = await getProcessDetails(
    [...processMap.values()].map((processInfo) => processInfo.ppid).filter(Boolean),
  )

  const services = uniqueListeners
    .map((listener) => {
      const processInfo = processMap.get(listener.pid)
      const parentInfo = processInfo?.ppid ? parentMap.get(processInfo.ppid) : undefined
      const lsof = lsofEvidenceMap.get(listenerEvidenceKey(listener.pid, listener.port))
      return enrichService(listener, processInfo, parentInfo, lsof)
    })
    .filter((service) => service.pid !== process.pid)
    .sort(sortServices)
  const diagnostics = await scanLsofProcesses(warnings)

  return {
    diagnostics,
    scannedAt: startedAt.toISOString(),
    platform: process.platform,
    scanner: scannerName(),
    services,
    warnings,
  }
}

export async function stopProcess(pid, force = false) {
  if (process.platform === 'win32') {
    const args = ['/PID', String(pid), '/T']
    if (force) args.push('/F')
    const result = await run('taskkill', args, 5000)
    if (!result.ok) {
      throw new Error(result.stderr || result.stdout || `taskkill failed for PID ${pid}`)
    }
    return { ok: true, pid, force, output: result.stdout.trim() }
  }

  try {
    process.kill(pid, force ? 'SIGKILL' : 'SIGTERM')
    return { ok: true, pid, force, signal: force ? 'SIGKILL' : 'SIGTERM' }
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : `Unable to stop PID ${pid}`)
  }
}

async function scanListeners(warnings) {
  if (process.platform === 'darwin') {
    const listeners = await scanMacNetstat(warnings)
    if (listeners.length) return listeners
    return scanLsof(warnings)
  }

  if (process.platform === 'win32') {
    return scanWindowsNetstat(warnings)
  }

  const ssListeners = await scanLinuxSs(warnings)
  if (ssListeners.length) return ssListeners
  const netstatListeners = await scanLinuxNetstat(warnings)
  if (netstatListeners.length) return netstatListeners
  return scanLsof(warnings)
}

function scannerName() {
  if (process.platform === 'darwin') return 'netstat + lsof + ps'
  if (process.platform === 'win32') return 'netstat + PowerShell'
  return 'ss/netstat/lsof + ps'
}

async function scanMacNetstat(warnings) {
  const result = await run('netstat', ['-anv', '-p', 'tcp'])
  if (!result.ok && !result.stdout) {
    warnings.push('macOS netstat failed; trying fallback scanner.')
    return []
  }

  return result.stdout
    .split(/\r?\n/)
    .filter((line) => /\bLISTEN\b/.test(line))
    .map((line) => {
      const match = line.match(
        /^(tcp\S+)\s+\d+\s+\d+\s+(\S+)\s+\S+\s+LISTEN\s+\d+\s+\d+\s+\d+\s+\d+\s+(.+?):(\d+)\s+/,
      )
      if (!match) return null
      const endpoint = parseEndpoint(match[2])
      if (!endpoint.port) return null
      return {
        host: endpoint.host,
        pid: Number(match[4]),
        port: endpoint.port,
        processName: cleanProcessName(match[3]),
        protocol: match[1].toUpperCase(),
        scannerSource: 'netstat',
      }
    })
    .filter(Boolean)
}

async function scanLinuxSs(warnings) {
  const result = await run('ss', ['-ltnp'])
  if (!result.ok && !result.stdout) {
    warnings.push('ss was unavailable; trying netstat.')
    return []
  }

  return result.stdout
    .split(/\r?\n/)
    .filter((line) => line.startsWith('LISTEN'))
    .map((line) => {
      const parts = line.trim().split(/\s+/)
      const endpoint = parseEndpoint(parts[3])
      const processMatch = line.match(/users:\(\("([^"]+)",pid=(\d+)/)
      if (!endpoint.port || !processMatch) return null
      return {
        host: endpoint.host,
        pid: Number(processMatch[2]),
        port: endpoint.port,
        processName: cleanProcessName(processMatch[1]),
        protocol: 'TCP',
        scannerSource: 'ss',
      }
    })
    .filter(Boolean)
}

async function scanLinuxNetstat(warnings) {
  const result = await run('netstat', ['-tulpn'])
  if (!result.ok && !result.stdout) {
    warnings.push('netstat fallback failed; trying lsof.')
    return []
  }

  return result.stdout
    .split(/\r?\n/)
    .filter((line) => /\bLISTEN\b/.test(line))
    .map((line) => {
      const parts = line.trim().split(/\s+/)
      const endpoint = parseEndpoint(parts[3])
      const processText = parts[6] ?? ''
      const processMatch = processText.match(/^(\d+)\/(.+)$/)
      if (!endpoint.port || !processMatch) return null
      return {
        host: endpoint.host,
        pid: Number(processMatch[1]),
        port: endpoint.port,
        processName: cleanProcessName(processMatch[2]),
        protocol: (parts[0] ?? 'tcp').toUpperCase(),
        scannerSource: 'netstat',
      }
    })
    .filter(Boolean)
}

async function scanWindowsNetstat(warnings) {
  const result = await run('netstat', ['-ano', '-p', 'tcp'])
  if (!result.ok && !result.stdout) {
    warnings.push('Windows netstat failed.')
    return []
  }

  return result.stdout
    .split(/\r?\n/)
    .filter((line) => /\bLISTENING\b/.test(line))
    .map((line) => {
      const match = line.match(/^\s*TCP\s+(\S+)\s+\S+\s+LISTENING\s+(\d+)/i)
      if (!match) return null
      const endpoint = parseEndpoint(match[1])
      if (!endpoint.port) return null
      return {
        host: endpoint.host,
        pid: Number(match[2]),
        port: endpoint.port,
        processName: 'process',
        protocol: 'TCP',
        scannerSource: 'netstat',
      }
    })
    .filter(Boolean)
}

async function scanLsof(warnings) {
  const result = await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'])
  if (!result.ok && !result.stdout) {
    warnings.push('lsof fallback failed or timed out.')
    return []
  }

  return parseLsofRows(result.stdout)
}

async function scanLsofEvidence(warnings) {
  if (process.platform === 'win32') return []

  const result = await run('lsof', ['-nP', '-iTCP', '-sTCP:LISTEN'], LSOF_EVIDENCE_TIMEOUT)
  if (!result.ok && !result.stdout) {
    warnings.push('lsof evidence scan timed out; listener rows still use the OS scanner.')
    return []
  }

  return parseLsofRows(result.stdout)
}

function parseLsofRows(stdout) {
  return stdout
    .split(/\r?\n/)
    .slice(1)
    .map((line) => {
      const raw = line.trim()
      if (!raw) return null
      const parts = line.trim().split(/\s+/)
      const processName = parts[0]
      const pid = Number(parts[1])
      const name = parts.slice(8).join(' ')
      const endpoint = parseEndpoint(name.replace(/\s+\([^)]*\)\s*$/, '').trim())
      if (!endpoint.port || !pid) return null
      return {
        fd: parts[3],
        host: endpoint.host,
        name,
        node: parts[7],
        pid,
        port: endpoint.port,
        processName: cleanProcessName(processName),
        protocol: 'TCP',
        raw,
        scannerSource: 'lsof',
        type: parts[4],
      }
    })
    .filter(Boolean)
}

async function getProcessDetails(pids) {
  const uniquePids = [...new Set(pids.map(Number).filter(Boolean))]
  const entries = await mapLimit(uniquePids, 8, async (pid) => {
    if (process.platform === 'win32') return getWindowsProcessDetails(pid)
    return getPosixProcessDetails(pid)
  })

  return new Map(entries.filter(Boolean).map((entry) => [entry.pid, entry]))
}

async function scanLsofProcesses(warnings) {
  if (process.platform === 'win32') return []

  const result = await run('ps', [
    '-axo',
    'pid=',
    '-o',
    'ppid=',
    '-o',
    'etime=',
    '-o',
    'comm=',
    '-o',
    'command=',
  ])

  if (!result.ok && !result.stdout) {
    warnings.push('Unable to inspect active lsof commands with ps.')
    return []
  }

  const entries = result.stdout
    .split(/\r?\n/)
    .map(parseProcessListLine)
    .filter((entry) => entry && isLsofProcess(entry))

  const parentMap = await getProcessDetails(entries.map((entry) => entry.ppid).filter(Boolean))
  const grandparentMap = await getProcessDetails(
    [...parentMap.values()].map((entry) => entry.ppid).filter(Boolean),
  )

  return entries
    .map((entry) => {
      const parentInfo = parentMap.get(entry.ppid)
      const grandparentInfo = parentInfo?.ppid ? grandparentMap.get(parentInfo.ppid) : undefined
      return enrichLsofProcess(entry, parentInfo, grandparentInfo)
    })
    .sort(sortLsofProcesses)
}

function parseProcessListLine(line) {
  const match = line.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/)
  if (!match) return null

  const ageSeconds = parseElapsed(match[3])
  return {
    ageSeconds,
    command: match[5].trim(),
    executable: match[4],
    pid: Number(match[1]),
    ppid: Number(match[2]),
    processName: cleanProcessName(basename(match[4])),
    startedAt: ageSeconds ? new Date(Date.now() - ageSeconds * 1000).toISOString() : undefined,
  }
}

function isLsofProcess(entry) {
  if (!entry || entry.pid === process.pid) return false
  if (entry.processName === 'lsof') return true
  return /^"?\/?(?:usr\/sbin\/|sbin\/|bin\/)?lsof(?:["\s]|$)/i.test(entry.command)
}

function enrichLsofProcess(entry, parentInfo, grandparentInfo) {
  const assessment = assessLsofProcess(entry, parentInfo, grandparentInfo)

  return {
    id: `lsof:${entry.pid}`,
    ageSeconds: entry.ageSeconds,
    command: entry.command,
    killAssessment: assessment.killAssessment,
    parentProcessName: parentInfo?.name,
    pid: entry.pid,
    ppid: entry.ppid,
    processName: 'lsof',
    protectedReason: assessment.protectedReason,
    recommendation: assessment.recommendation,
    reasons: assessment.reasons,
    sourceSummary: diagnosticSourceSummary(parentInfo, grandparentInfo),
    startedAt: entry.startedAt,
    stoppable: assessment.killAssessment.verdict !== 'do-not-stop',
    verdict: assessment.verdict,
  }
}

async function getPosixProcessDetails(pid) {
  const result = await run('ps', [
    '-p',
    String(pid),
    '-o',
    'pid=',
    '-o',
    'ppid=',
    '-o',
    'etime=',
    '-o',
    'command=',
  ])

  const line = result.stdout.trim().split(/\r?\n/)[0]
  const match = line?.match(/^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/)
  if (!match) return null

  const command = match[4].trim()
  const ageSeconds = parseElapsed(match[3])

  return {
    ageSeconds,
    command,
    cwd: getLinuxCwd(pid),
    name: nameFromCommand(command),
    pid: Number(match[1]),
    ppid: Number(match[2]),
    startedAt: ageSeconds ? new Date(Date.now() - ageSeconds * 1000).toISOString() : undefined,
  }
}

async function getWindowsProcessDetails(pid) {
  const script = [
    `$p = Get-CimInstance Win32_Process -Filter "ProcessId = ${pid}"`,
    'if ($p) {',
    '$p | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Json -Compress',
    '}',
  ].join('; ')
  const result = await run('powershell.exe', ['-NoProfile', '-Command', script])
  if (!result.stdout.trim()) return null

  try {
    const info = JSON.parse(result.stdout)
    const command = info.CommandLine || info.ExecutablePath || info.Name || 'process'
    const ageSeconds = info.CreationDate
      ? Math.max(0, Math.floor((Date.now() - new Date(info.CreationDate).getTime()) / 1000))
      : undefined

    return {
      ageSeconds,
      command,
      name: info.Name || nameFromCommand(command),
      pid: Number(info.ProcessId),
      ppid: Number(info.ParentProcessId),
      startedAt: info.CreationDate ? new Date(info.CreationDate).toISOString() : undefined,
    }
  } catch {
    return null
  }
}

function enrichService(listener, processInfo, parentInfo, lsofEvidence) {
  const command = processInfo?.command ?? listener.processName
  const processName = preferredProcessName(processInfo?.name, listener.processName)
  const classification = classify({
    command,
    cwd: processInfo?.cwd,
    port: listener.port,
    processName,
  })
  const protectedReason = protectedReasonFor(processName, listener.pid)
  const projectPath = inferProjectPath(command)
  const finalProtectedReason = protectedReason ?? classification.protectedReason
  const killAssessment = assessListenerKillSafety({
    category: classification.category,
    command,
    confidence: classification.confidence,
    protectedReason: finalProtectedReason,
    bucket: classification.bucket,
    processName,
  })
  const scannerSources = [
    listener.scannerSource,
    lsofEvidence ? 'lsof' : undefined,
    processInfo ? 'ps' : undefined,
  ].filter(Boolean)

  return {
    id: `${listener.protocol}:${listener.port}:${listener.pid}`,
    bucket: classification.bucket,
    category: classification.category,
    ageSeconds: processInfo?.ageSeconds,
    command,
    confidence: classification.confidence,
    confidenceReasons: classification.reasons,
    cwd: processInfo?.cwd,
    host: listener.host,
    killAssessment,
    lsof: lsofEvidence
      ? {
          fd: lsofEvidence.fd,
          name: lsofEvidence.name,
          node: lsofEvidence.node,
          raw: lsofEvidence.raw,
          type: lsofEvidence.type,
        }
      : undefined,
    parentProcessName: parentInfo?.name,
    pid: listener.pid,
    port: listener.port,
    ppid: processInfo?.ppid,
    processName,
    projectName: projectPath ? basename(projectPath) : undefined,
    projectPath,
    protectedReason: finalProtectedReason,
    recommendation: classification.recommendation,
    protocol: listener.protocol.replace(/^TCP\d+$/i, 'TCP'),
    scannerSources,
    serviceName: classification.name,
    sourceSummary: sourceSummaryFor(command, processInfo?.cwd, parentInfo),
    startedAt: processInfo?.startedAt,
    stoppable: killAssessment.verdict !== 'do-not-stop',
  }
}

function assessListenerKillSafety({
  bucket,
  category,
  command,
  confidence,
  processName,
  protectedReason,
}) {
  if (protectedReason || bucket === 'normal') {
    return {
      label: 'Do not kill',
      reason: protectedReason ?? 'This looks like normal system or app plumbing.',
      tone: 'protected',
      verdict: 'do-not-stop',
    }
  }

  if (category === 'database') {
    return {
      label: 'Check first',
      reason: 'Database listeners can be serving active apps or local data.',
      tone: 'caution',
      verdict: 'inspect-first',
    }
  }

  if (category === 'tunnel') {
    return {
      label: 'Check first',
      reason: 'Tunnels may be exposing a local workflow or callback URL.',
      tone: 'caution',
      verdict: 'inspect-first',
    }
  }

  if (category === 'unknown' || bucket === 'unsure') {
    return {
      label: 'Inspect first',
      reason: 'watsOn does not have enough owner evidence for this listener.',
      tone: 'caution',
      verdict: 'inspect-first',
    }
  }

  if (category === 'remote-debug') {
    return {
      label: 'Can stop',
      reason: 'Developer debugging listeners are usually disposable when that session is done.',
      tone: 'safe',
      verdict: 'safe-to-stop',
    }
  }

  if (confidence === 'high' || /node|npm|pnpm|yarn|vite|next|python|ruby|bun|deno/i.test(command)) {
    return {
      label: 'Can stop',
      reason: 'This looks like a user-started local development process.',
      tone: 'safe',
      verdict: 'safe-to-stop',
    }
  }

  return {
    label: 'Check first',
    reason: `${displayName(processName)} is not protected, but the source evidence is incomplete.`,
    tone: 'caution',
    verdict: 'inspect-first',
  }
}

function assessLsofProcess(entry, parentInfo, grandparentInfo) {
  const parentName = parentInfo?.name ?? ''
  const source =
    parentName === 'lsof' && grandparentInfo?.name
      ? `Forked by lsof from ${grandparentInfo.name}.`
      : parentName
        ? `Started by ${parentName}.`
        : 'Parent process is unknown.'
  const isWatsonScan = entry.ppid === process.pid || /server\/index\.js --dev|watsOn/i.test(parentInfo?.command ?? '')
  const isStale = (entry.ageSeconds ?? 0) >= STALE_LSOF_SECONDS
  const inspectingNetwork = /-i|TCP|UDP|LISTEN|:\d+/i.test(entry.command)

  if (isWatsonScan) {
    return {
      killAssessment: {
        label: 'Do not kill',
        reason: 'This is the current watsOn evidence scan.',
        tone: 'protected',
        verdict: 'do-not-stop',
      },
      protectedReason: 'watsOn scan in progress',
      recommendation: 'Leave this alone; it should disappear when the scan finishes.',
      reasons: ['Parent process is the watsOn API.'],
      verdict: 'good',
    }
  }

  if (isStale) {
    return {
      killAssessment: {
        label: 'Can kill',
        reason: 'lsof is a diagnostic command and this one has been running longer than expected.',
        tone: 'safe',
        verdict: 'safe-to-stop',
      },
      recommendation: 'Safe to stop if you did not intentionally start this inspection.',
      reasons: [source, inspectingNetwork ? 'It is inspecting network listeners.' : 'It is an lsof inspection command.'],
      verdict: 'stale',
    }
  }

  return {
    killAssessment: {
      label: 'Wait',
      reason: 'Short-lived lsof scans are normal while something inspects the machine.',
      tone: 'caution',
      verdict: 'inspect-first',
    },
    recommendation: 'Give it a moment; kill it only if it sticks around or repeats unexpectedly.',
    reasons: [source, 'It has not been running long enough to call stuck.'],
    verdict: 'active',
  }
}

function classify({ command, cwd, port, processName }) {
  const haystack = `${processName} ${command}`
  const projectEvidence = projectEvidenceFor(command, cwd)
  const explicitBrowserAutomation = /remote-debugging-port|playwright|puppeteer|cypress/i.test(haystack)

  if (isSystemProcess(processName) || isNormalAppPlumbing(command, processName)) {
    return {
      bucket: 'normal',
      category: normalCategoryFor(command, processName),
      confidence: 'low',
      name: displayName(processName),
      protectedReason: 'Normal system or app service',
      recommendation: 'Hidden by default because this looks like normal OS or app plumbing.',
      reasons: [normalReasonFor(command, processName)],
    }
  }

  const matchedRule = devRules.find((rule) => rule.test.test(haystack))

  if (matchedRule) {
    return {
      bucket: 'likely-yours',
      category: matchedRule.category,
      confidence: 'high',
      name: matchedRule.name,
      recommendation: 'Worth checking; this looks intentionally started for local development.',
      reasons: [projectEvidence ?? `Command contains ${matchedRule.name}.`],
    }
  }

  if (isBrowserProcess(command, processName) && !explicitBrowserAutomation) {
    return {
      bucket: 'normal',
      category: 'browser-helper',
      confidence: 'low',
      name: displayName(processName),
      protectedReason: 'Browser helper service',
      recommendation: 'Hidden by default unless browser automation is detected.',
      reasons: ['Process looks like normal browser helper plumbing.'],
    }
  }

  if (projectEvidence) {
    return {
      bucket: 'likely-yours',
      category: 'dev-server',
      confidence: 'high',
      name: displayName(processName),
      recommendation: 'Worth checking; it is tied to a user project path.',
      reasons: [projectEvidence],
    }
  }

  const known = knownPorts.get(port)
  if (known) {
    return {
      bucket: 'likely-yours',
      category: known[1],
      confidence: 'medium',
      name: known[0],
      recommendation: 'Listening locally on a port commonly used by developer tooling.',
      reasons: [`Port ${port} is commonly used by local developer tooling.`],
    }
  }

  if (/node|npm|pnpm|yarn|python|ruby|java|go|cargo|deno|bun/i.test(haystack)) {
    return {
      bucket: 'likely-yours',
      category: 'dev-server',
      confidence: 'medium',
      name: displayName(processName),
      recommendation: 'Worth checking; the process family often runs local development servers.',
      reasons: ['Process family often runs developer services.'],
    }
  }

  return {
    bucket: 'unsure',
    category: 'unknown',
    confidence: 'low',
    name: 'Unknown local listener',
    recommendation: 'Visible because it is listening locally, but there is not enough evidence to judge it.',
    reasons: ['Listening TCP service with no strong developer-tool signal.'],
  }
}

function protectedReasonFor(processName, pid) {
  if (pid <= 1) return 'Protected OS process'
  if (pid === process.pid) return 'watsOn API process'
  if (isSystemProcess(processName)) return 'Likely system service'
  if (/^com\.apple\.|apple|kernel|WindowServer/i.test(processName)) return 'Likely system service'
  return undefined
}

function isSystemProcess(processName) {
  return systemProcessNames.has(processName) || /tailscale|rapportd|symptomsd/i.test(processName)
}

function isNormalAppPlumbing(command, processName) {
  return normalAppPatterns.some((pattern) => pattern.test(`${processName} ${command}`))
}

function isBrowserProcess(command, processName) {
  return browserPatterns.some((pattern) => pattern.test(`${processName} ${command}`))
}

function normalCategoryFor(command, processName) {
  const haystack = `${processName} ${command}`
  if (/Microsoft AutoUpdate|GoogleUpdater|GoogleSoftwareUpdate|ksadmin|ksfetch/i.test(haystack)) {
    return 'app-updater'
  }
  if (isBrowserProcess(command, processName)) return 'browser-helper'
  if (/\/Applications\/[^/]+\.app\/Contents\/.*Helper/i.test(haystack)) return 'app-service'
  if (/\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i.test(haystack)) return 'app-service'
  if (/\/Users\/[^/]+\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i.test(haystack)) return 'app-service'
  return 'system'
}

function normalReasonFor(command, processName) {
  const haystack = `${processName} ${command}`
  if (isSystemProcess(processName)) return 'Process is known system or networking plumbing.'
  if (/\/System\//i.test(command)) return 'Path starts inside /System.'
  if (/\/usr\/libexec\//i.test(command)) return 'Path starts inside /usr/libexec.'
  if (/\/Library\/Apple\//i.test(command)) return 'Path starts inside /Library/Apple.'
  if (/\/Applications\/[^/]+\.app\/Contents\/.*Helper/i.test(haystack)) {
    return 'Process looks like an app helper.'
  }
  if (/\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i.test(haystack)) {
    return 'Process looks like an app support helper.'
  }
  if (/\/Users\/[^/]+\/Library\/Application Support\/[^/]+\/[^/]+\.app\/Contents\//i.test(haystack)) {
    return 'Process looks like an app support helper.'
  }
  if (/Microsoft AutoUpdate/i.test(haystack)) return 'Process is Microsoft AutoUpdate.'
  if (/GoogleUpdater|GoogleSoftwareUpdate|ksadmin|ksfetch/i.test(haystack)) {
    return 'Process is Google updater plumbing.'
  }
  return 'Looks like normal system or app plumbing.'
}

function projectEvidenceFor(command, cwd) {
  const evidenceTarget = `${cwd ?? ''} ${command}`
  const home = homedir().replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  const homeProject = new RegExp(`${home}/(?:Documents|Developer|DEV|Dev|dev|Code|Projects|repos|Sites)/`, 'i')

  if (homeProject.test(evidenceTarget)) return 'Path is inside a user project folder.'
  if (/\/(?:workspaces?|repos?|projects?|apps?)\//i.test(evidenceTarget)) {
    return 'Path contains a project-like directory.'
  }
  if (/\b(package\.json|node_modules|pnpm-lock\.yaml|yarn\.lock|vite\.config|next\.config)\b/i.test(evidenceTarget)) {
    return 'Command references JavaScript project files.'
  }
  if (/\/var\/folders\/.*(?:timeline-factory|supabase|postgres|vite|next|playwright|cypress)/i.test(evidenceTarget)) {
    return 'Command points at a temporary developer-tool workspace.'
  }
  return undefined
}

function sourceSummaryFor(command, cwd, parentInfo) {
  const projectPath = inferProjectPath(`${cwd ?? ''} ${command}`)
  if (projectPath) return `Project path: ${projectPath}`
  if (cwd) return `Working directory: ${cwd}`
  if (parentInfo?.name) return `Parent process: ${parentInfo.name}`
  const executable = command.match(/^"([^"]+)"/)?.[1] ?? command.split(/\s+/)[0]
  if (executable) return `Executable: ${executable}`
  return 'Source unknown'
}

function diagnosticSourceSummary(parentInfo, grandparentInfo) {
  if (parentInfo?.name === 'lsof' && grandparentInfo?.name) {
    return `Parent chain: ${grandparentInfo.name} -> lsof`
  }

  if (parentInfo?.name) return `Parent process: ${parentInfo.name}`
  return 'Parent process unknown'
}

function listenerEvidenceKey(pid, port) {
  return `${Number(pid)}:${Number(port)}`
}

function dedupeListeners(listeners) {
  const byKey = new Map()

  for (const listener of listeners) {
    if (!listener.pid || !listener.port) continue
    const key = `${listener.pid}:${listener.port}:${listener.protocol.replace(/\d+$/g, '')}`
    const existing = byKey.get(key)

    if (!existing) {
      byKey.set(key, listener)
      continue
    }

    if (existing.host === '*' || existing.host === '0.0.0.0') continue
    byKey.set(key, { ...existing, host: listener.host })
  }

  return [...byKey.values()]
}

function parseEndpoint(endpoint) {
  const normalized = endpoint.replace(/^\[|\]$/g, '')

  if (normalized.includes(']:')) {
    const match = endpoint.match(/^\[(.*)]:(\d+)$/)
    if (match) return { host: normalizeHost(match[1]), port: Number(match[2]) }
  }

  const dotIndex = normalized.lastIndexOf('.')
  if (dotIndex >= 0 && /^\d+$/.test(normalized.slice(dotIndex + 1))) {
    return {
      host: normalizeHost(normalized.slice(0, dotIndex)),
      port: Number(normalized.slice(dotIndex + 1)),
    }
  }

  const colonMatch = normalized.match(/^(.*):(\d+)$/)
  if (colonMatch) {
    return { host: normalizeHost(colonMatch[1]), port: Number(colonMatch[2]) }
  }

  return { host: normalizeHost(normalized), port: undefined }
}

function normalizeHost(host) {
  if (!host || host === '*' || host === '*.*') return '0.0.0.0'
  return host
}

function cleanProcessName(name) {
  return (name || 'process').trim().replace(/^\//, '').replace(/\s+$/, '')
}

function preferredProcessName(processName, listenerName) {
  const cleanedProcess = cleanProcessName(processName)
  const cleanedListener = cleanProcessName(listenerName)
  if (cleanedProcess === 'Application' && cleanedListener !== 'process') return cleanedListener
  return cleanedProcess || cleanedListener
}

function displayName(name) {
  if (!name) return 'Local service'
  return name
    .replace(/\.(js|mjs|cjs)$/i, '')
    .replace(/-/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase())
}

function nameFromCommand(command) {
  const executable = command.match(/^"([^"]+)"/)?.[1] ?? command.split(/\s+/)[0] ?? 'process'
  return cleanProcessName(basename(executable))
}

function inferProjectPath(command) {
  const candidates = [
    ...command.matchAll(/(?:^|\s)(\/[^\s"'`]+(?:\/[^\s"'`]+)*)(?:\s|$)/g),
    ...command.matchAll(/(?:^|\s)(~\/[^\s"'`]+(?:\/[^\s"'`]+)*)(?:\s|$)/g),
  ]
    .map((match) => match[1])
    .filter((value) => !/\/(bin|node_modules|usr|opt|System|Library)(\/|$)/.test(value))

  return candidates[0]
}

function getLinuxCwd(pid) {
  if (process.platform !== 'linux') return undefined
  try {
    return process.binding('fs').readlink(`/proc/${pid}/cwd`)
  } catch {
    return undefined
  }
}

function parseElapsed(etime) {
  if (!etime) return undefined
  const [dayPart, timePart = dayPart] = etime.includes('-') ? etime.split('-') : [undefined, etime]
  const parts = timePart.split(':').map(Number)
  let seconds = 0

  if (parts.length === 3) {
    seconds += parts[0] * 3600 + parts[1] * 60 + parts[2]
  } else if (parts.length === 2) {
    seconds += parts[0] * 60 + parts[1]
  } else if (parts.length === 1) {
    seconds += parts[0]
  }

  if (dayPart) seconds += Number(dayPart) * 86400
  return Number.isFinite(seconds) ? seconds : undefined
}

function sortServices(a, b) {
  const categoryWeight = {
    'dev-server': 0,
    database: 1,
    'ai-tool': 2,
    tunnel: 3,
    'remote-debug': 4,
    unknown: 5,
    'browser-helper': 6,
    'app-updater': 7,
    'app-service': 8,
    system: 9,
  }
  const confidenceWeight = { high: 0, medium: 1, low: 2 }
  const bucketWeight = { 'likely-yours': 0, unsure: 1, normal: 2 }

  return (
    bucketWeight[a.bucket] - bucketWeight[b.bucket] ||
    categoryWeight[a.category] - categoryWeight[b.category] ||
    confidenceWeight[a.confidence] - confidenceWeight[b.confidence] ||
    a.port - b.port
  )
}

function sortLsofProcesses(a, b) {
  const verdictWeight = { stale: 0, active: 1, good: 2 }

  return (
    (verdictWeight[a.verdict] ?? 3) - (verdictWeight[b.verdict] ?? 3) ||
    (b.ageSeconds ?? 0) - (a.ageSeconds ?? 0) ||
    a.pid - b.pid
  )
}

async function mapLimit(items, limit, worker) {
  const results = []
  let index = 0

  async function runNext() {
    const current = index
    index += 1
    if (current >= items.length) return
    results[current] = await worker(items[current])
    await runNext()
  }

  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runNext))
  return results
}

function run(command, args, timeout = COMMAND_TIMEOUT) {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      { maxBuffer: MAX_BUFFER, timeout, windowsHide: true },
      (error, stdout = '', stderr = '') => {
        resolve({
          ok: !error,
          stdout,
          stderr,
          error,
        })
      },
    )
  })
}
